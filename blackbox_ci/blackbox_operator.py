import time
import urllib.parse
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, cast

import requests

from blackbox_ci.blackbox_api import BlackBoxAPI
from blackbox_ci.consts import (
    AUTH_APIKEY_NAME_KEY,
    AUTH_APIKEY_PLACE_KEY,
    AUTH_APIKEY_VALUE_KEY,
    AUTH_COOKIES_KEY,
    AUTH_FORM_URL_KEY,
    AUTH_FORM_X_PATH_KEY,
    AUTH_PASSWORD_FIELD_KEY,
    AUTH_PASSWORD_KEY,
    AUTH_REGEXP_OF_SUCCESS_KEY,
    AUTH_SUBMIT_VALUE_KEY,
    AUTH_SUCCESS_STRING_KEY,
    AUTH_SUCCESS_URL_KEY,
    AUTH_TOKEN_KEY,
    AUTH_TYPE_KEY,
    AUTH_USERNAME_FIELD_KEY,
    AUTH_USERNAME_KEY,
    AUTO_CREATE_OPTION,
    HTML_TEMPLATES_MAP,
    IDLE_SCAN_STATUSES,
    PAGE_VULNS_LIMIT,
    RESET_API_PROFILE,
    RESET_AUTH_PROFILE,
    TARGET_URL_OPTION,
)
from blackbox_ci.errors import BlackBoxError, BlackBoxHTTPError, BlackBoxUrlError
from blackbox_ci.files import save_report_content
from blackbox_ci.types import (
    ApiKey,
    ApiKeyPlace,
    APIProfile,
    Authentication,
    AuthenticationProfile,
    AuthenticationType,
    Bearer,
    ErrorReport,
    GroupCve,
    GroupErrorPage,
    GroupIssue,
    HtmlAutoForm,
    HtmlFormBased,
    HttpBasic,
    RawCookie,
    ReportExtension,
    ReportLocale,
    ReportScanStatus,
    ReportTemplateShortname,
    ReturnType,
    ScanProfile,
    ScanReport,
    ScanStatus,
    Site,
    SiteSettings,
    TargetVulns,
    UserGroupType,
    VulnCommon,
    VulnCve,
    VulnErrorPage,
    VulnGroup,
    VulnIssue,
)
from blackbox_ci.urls import normalize_url


def ensure_attrs_set(
    *attrs: str,
) -> Callable[[Callable[..., ReturnType]], Callable[..., ReturnType]]:
    def decorator(func: Callable[..., ReturnType]) -> Callable[..., ReturnType]:
        @wraps(func)
        def wrapper(self: 'BlackBoxOperator', *args: Any, **kwargs: Any) -> ReturnType:
            if not all(hasattr(self, attr) for attr in attrs):
                verbose = ', '.join(attrs)
                raise RuntimeError(f'{verbose} not set')
            return func(self, *args, **kwargs)

        return wrapper

    return decorator


class BlackBoxOperator:
    _site_uuid: str
    _scan_id: int
    _group_uuid: str

    def __init__(self, *, url: str, api: BlackBoxAPI) -> None:
        self._ui_base_url = url
        self._api = api
        self._scan_finished: bool = False

    def set_user_group(self, *, group_uuid: Optional[str]) -> None:
        user_type_groups = [
            group
            for group in self._api.get_groups()
            if group['type'] == UserGroupType.USER
            and (group_uuid is None or group['uuid'] == group_uuid)
        ]
        if len(user_type_groups) == 1:
            group_uuid = user_type_groups[0]['uuid']
        elif group_uuid is None:
            raise BlackBoxError(
                'the group UUID for site is required, '
                'use UI to create new group or choose existing one'
            )
        else:
            raise BlackBoxError(
                'the group with the UUID specified was not found, '
                'use UI to create new or choose existing one'
            )
        self._group_uuid = group_uuid

    @ensure_attrs_set('_group_uuid')
    def get_target(self, *, url: str) -> Optional[Site]:
        normalized_url = normalize_url(url)
        sites = self._api.get_sites()
        for site in sites:
            if (
                site['url'] == normalized_url
                and site['group']['uuid'] == self._group_uuid
            ):
                return site
        return None

    @ensure_attrs_set('_site_uuid')
    def set_scan(self, *, scan_id: Optional[int]) -> None:
        site = self._api.get_site(site_uuid=self._site_uuid)
        if not site['lastScan']:
            raise BlackBoxError('this site has not yet been scanned')
        elif scan_id and site['lastScan']['id'] < scan_id:
            raise BlackBoxError('the specified scan was not found')

        if scan_id and scan_id < site['lastScan']['id']:
            scan = self._api.get_scan(site_uuid=self._site_uuid, scan_id=scan_id)
            self._scan_id = scan_id
            self._scan_finished = scan['status'] in IDLE_SCAN_STATUSES
        else:
            self._scan_id = site['lastScan']['id']
            self._scan_finished = site['lastScan']['status'] in IDLE_SCAN_STATUSES

    def set_target(
        self,
        *,
        url: Optional[str],
        uuid: Optional[str],
        group_uuid: Optional[str],
        auto_create: bool,
    ) -> None:
        if uuid:
            self.set_target_by_uuid(uuid=uuid, group_uuid=group_uuid)
        elif url:
            self.set_user_group(group_uuid=group_uuid)
            self.set_target_by_url(url=url, auto_create=auto_create)
        else:
            raise RuntimeError('uuid or url required to set target')

    def set_target_by_uuid(self, *, uuid: str, group_uuid: Optional[str]) -> None:
        if group_uuid:
            self.set_user_group(group_uuid=group_uuid)  # ensure group exists
        sites = self._api.get_sites()
        for site in sites:
            if site['uuid'] == uuid and (
                not group_uuid or site['group']['uuid'] == group_uuid
            ):
                self._group_uuid = site['group']['uuid']
                self._site_uuid = uuid
                return

        group_verbose = ' in the group' if group_uuid else ''
        raise BlackBoxError(
            f'the site with the UUID specified was not found{group_verbose}, '
            'choose existing one via UI, use UI to create new one manually '
            f'or use {TARGET_URL_OPTION} option and {AUTO_CREATE_OPTION} flag '
            f'to do so automatically'
        )

    @ensure_attrs_set('_group_uuid')
    def set_target_by_url(self, *, url: str, auto_create: bool) -> None:
        site: Optional[Site] = self.get_target(url=url)
        if site is None:
            if not auto_create:
                raise BlackBoxError(
                    'the site with the URL specified was not found in the group, '
                    'use UI to create one manually, '
                    f'or use {AUTO_CREATE_OPTION} flag to do so automatically'
                )
            self._site_uuid = self._api.add_site(
                target_url=url, group_uuid=self._group_uuid
            )
        else:
            self._site_uuid = site['uuid']

    @ensure_attrs_set('_site_uuid')
    def set_site_settings(
        self,
        *,
        profile_uuid: Optional[str],
        auth_uuid: Optional[str],
        api_profile_uuid: Optional[str],
    ) -> None:
        current_settings = self._api.get_site_settings(site_uuid=self._site_uuid)
        new_profile_uuid = self._get_new_profile_uuid(
            current_settings=current_settings, profile_uuid=profile_uuid
        )
        new_auth_uuid = self._get_new_auth_uuid(
            current_settings=current_settings, auth_uuid=auth_uuid
        )
        new_api_profile_uuid = self._get_new_api_profile_uuid(
            current_settings=current_settings, api_profile_uuid=api_profile_uuid
        )
        if self._is_settings_changed(
            current_settings=current_settings,
            new_profile_uuid=new_profile_uuid,
            new_auth_uuid=new_auth_uuid,
            new_api_profile_uuid=new_api_profile_uuid,
        ):
            self._api.set_site_settings(
                site_uuid=self._site_uuid,
                profile_uuid=new_profile_uuid,
                authentication_uuid=new_auth_uuid,
                api_profile_uuid=new_api_profile_uuid,
            )

    @ensure_attrs_set('_group_uuid')
    def create_auth_profile(self, *, auth_data: Dict[str, str]) -> str:
        _raw_auth_data = auth_data.copy()
        auth_type = self._pop_auth_type_from_raw_data(raw_auth_data=_raw_auth_data)
        auth_json = self._convert_auth_json(
            raw_auth_data=_raw_auth_data, auth_type=auth_type
        )
        if _raw_auth_data:
            verbose = ', '.join(_raw_auth_data.keys())
            raise BlackBoxError(
                f'following fields unsupported for this auth type: {verbose}'
            )

        group = self._api.get_group(group_uuid=self._group_uuid)
        auth_profile_uuid = self._api.create_auth_profile(
            auth_type=auth_type.name,
            auth_field=auth_type.value,
            authentication=auth_json,
            group_uuid=self._group_uuid,
            name=group['name'],
        )
        return auth_profile_uuid

    @ensure_attrs_set('_site_uuid')
    def is_target_busy(self) -> bool:
        site = self._api.get_site(site_uuid=self._site_uuid)
        last_scan = site['lastScan']
        if not last_scan:
            return False
        return last_scan['status'] not in IDLE_SCAN_STATUSES

    @ensure_attrs_set('_site_uuid', '_scan_id')
    def is_scan_busy(self) -> bool:
        scan = self._api.get_scan(site_uuid=self._site_uuid, scan_id=self._scan_id)
        return scan['status'] not in IDLE_SCAN_STATUSES

    @ensure_attrs_set('_site_uuid', '_scan_id')
    def is_scan_ok(self) -> bool:
        scan = self._api.get_scan(site_uuid=self._site_uuid, scan_id=self._scan_id)
        return scan['status'] == ScanStatus.finished and scan['errorReason'] is None

    @ensure_attrs_set('_site_uuid', '_scan_id')
    def get_scan_error_reason(self) -> Optional[str]:
        scan = self._api.get_scan(site_uuid=self._site_uuid, scan_id=self._scan_id)
        return scan['errorReason']

    @ensure_attrs_set('_site_uuid')
    def ensure_target_is_idle(self, *, previous: str) -> None:
        if not self.is_target_busy():
            return

        if previous == 'fail':
            raise BlackBoxError('the target is busy')

        if previous == 'stop':
            self._api.stop_scan(site_uuid=self._site_uuid)
        # previous is either 'stop' or 'wait'
        self._wait_for_target()

    @ensure_attrs_set('_site_uuid')
    def start_scan(self) -> None:
        self._scan_id = self._api.start_scan(site_uuid=self._site_uuid)
        self._scan_finished = False

    @ensure_attrs_set('_site_uuid', '_scan_id')
    def get_scan_report(
        self,
        *,
        target_url: Optional[str],
        shared_link: bool,
        report_path: Optional[str],
        partial_results: bool = False,
    ) -> ScanReport:
        site = self._api.get_site(site_uuid=self._site_uuid)
        scan = self._api.get_scan(site_uuid=self._site_uuid, scan_id=self._scan_id)

        report: ScanReport = {
            'target_url': target_url if target_url else site['url'],
            'target_uuid': self._site_uuid,
            'url': self._scan_url,
            'scan_status': ReportScanStatus[scan['status']]
            if scan['status'] in IDLE_SCAN_STATUSES
            else ReportScanStatus.in_progress,
            'score': None,
            'sharedLink': None,
            'report_path': report_path,
            'vulns': None,
            'errors': None,
        }
        if self._scan_finished or partial_results:
            report['score'] = self._api.get_score(
                site_uuid=self._site_uuid, scan_id=self._scan_id
            )
            report['vulns'] = self._collect_vulns()
        if shared_link:
            report['sharedLink'] = self._create_shared_link()
        return report

    def get_error_report(
        self,
        *,
        target_url: Optional[str],
        target_uuid: Optional[str],
        shared_link: bool,
        report_path: Optional[str],
        error: BlackBoxError,
    ) -> ScanReport:
        errors = [self._convert_error_json(error=error)]
        report: ScanReport = {
            'target_url': target_url,
            'target_uuid': self._site_uuid
            if not target_uuid and hasattr(self, '_site_uuid')
            else target_uuid,
            'url': None,
            'scan_status': None,
            'score': None,
            'sharedLink': None,
            'report_path': report_path,
            'vulns': None,
            'errors': errors,
        }

        if hasattr(self, '_site_uuid') and hasattr(self, '_scan_id'):
            report['url'] = self._scan_url

            try:
                report['target_url'] = (
                    self._api.get_site(site_uuid=self._site_uuid)['url']
                    if not target_url
                    else target_url
                )
                scan = self._api.get_scan(
                    site_uuid=self._site_uuid, scan_id=self._scan_id
                )
                report['scan_status'] = (
                    ReportScanStatus[scan['status']]
                    if scan['status'] in IDLE_SCAN_STATUSES
                    else ReportScanStatus.in_progress
                )
                if shared_link:
                    report['sharedLink'] = self._create_shared_link()
                report['score'] = self._api.get_score(
                    site_uuid=self._site_uuid, scan_id=self._scan_id
                )
                report['vulns'] = self._collect_vulns()
            except BlackBoxHTTPError as request_error:
                errors.append(self._convert_error_json(error=request_error))
        return report

    @classmethod
    def get_init_error_report(
        cls,
        *,
        target_url: Optional[str],
        target_uuid: Optional[str],
        report_path: Optional[str],
        error: BlackBoxError,
    ) -> ScanReport:
        errors = [cls._convert_error_json(error=error)]
        report: ScanReport = {
            'target_url': target_url,
            'target_uuid': target_uuid,
            'url': None,
            'scan_status': None,
            'score': None,
            'sharedLink': None,
            'report_path': report_path,
            'vulns': None,
            'errors': errors,
        }
        return report

    @ensure_attrs_set('_site_uuid', '_scan_id')
    def generate_report_file(
        self,
        *,
        locale: ReportLocale,
        template_shortname: ReportTemplateShortname,
        output_dir: str,
    ) -> str:
        if not self._scan_finished:
            raise BlackBoxError('scan must be finished or stopped to generate report')

        if template_shortname in HTML_TEMPLATES_MAP.keys():
            extension = ReportExtension.HTML
            report_content = self._api.get_html_report_content(
                site_uuid=self._site_uuid,
                scan_id=self._scan_id,
                locale=locale,
                template=HTML_TEMPLATES_MAP[template_shortname],
            )
        else:
            extension = ReportExtension.SARIF
            report_content = self._api.get_sarif_report_content(
                site_uuid=self._site_uuid, scan_id=self._scan_id, locale=locale
            )
        report_path = save_report_content(
            report_dir=output_dir,
            report_content=report_content,
            target_name=self._api.get_site(site_uuid=self._site_uuid)['name'],
            extension=extension,
            locale=locale,
            template_shortname=template_shortname,
        )
        return report_path

    @ensure_attrs_set('_site_uuid', '_scan_id')
    def wait_for_scan(self) -> None:
        while self.is_scan_busy():
            time.sleep(2.0)
        self._scan_finished = True
        if not self.is_scan_ok():
            error_reason: Optional[str] = self.get_scan_error_reason()
            verbose = (
                f'the error reason is "{error_reason}"'
                if error_reason
                else f'scan status is "{ReportScanStatus.stopped.value}"'
            )
            raise BlackBoxError(
                f'the scan did not succeed, {verbose}, '
                f'see UI for details: {self._scan_url}'
            )

    @ensure_attrs_set('_site_uuid')
    def _wait_for_target(self) -> None:
        while self.is_target_busy():
            time.sleep(2.0)

    @ensure_attrs_set('_site_uuid', '_scan_id')
    def _create_shared_link(self) -> str:
        shared_link_uuid = self._api.create_shared_link(
            site_uuid=self._site_uuid, scan_id=self._scan_id
        )
        shared_link = urllib.parse.urljoin(
            self._ui_base_url, f'/shared/{shared_link_uuid}'
        )
        return shared_link

    @ensure_attrs_set('_site_uuid', '_scan_id')
    def _collect_vulns(self) -> TargetVulns:  # noqa: C901
        group_list = self._api.get_vuln_groups(
            site_uuid=self._site_uuid, scan_id=self._scan_id
        )
        vuln_report: TargetVulns = {
            'issue_groups': [],
            'error_page_groups': [],
            'cve_groups': [],
        }

        for group_info in group_list:
            issue_type = group_info['issueType']

            if issue_type == 'issue':
                issue_group = self._create_group_issue(group_info=group_info)
                vuln_report['issue_groups'].append(issue_group)

            elif issue_type == 'error_page':
                error_page_group = self._create_group_error_page(group_info=group_info)
                vuln_report['error_page_groups'].append(error_page_group)

            elif issue_type == 'cve':
                cve_group = self._create_group_cve(group_info=group_info)
                vuln_report['cve_groups'].append(cve_group)

        return vuln_report

    def _create_group_issue(self, *, group_info: VulnGroup) -> GroupIssue:
        group: GroupIssue = {
            'severity': group_info['severity'],
            'category': group_info['categoryLocaleKey'],
            'group_title': group_info['groupTitle'],
            'vulns': [],
        }

        request_key = group_info['requestKey']
        request_key = cast(str, request_key)

        severity = group_info['severity']
        count = group_info['count']

        if count == 1:
            group['vulns'].append(self._convert_issue(vuln=group_info['vulnerability']))
        else:
            group['vulns'].extend(
                self._read_issue_vulns(request_key=request_key, severity=severity)
            )
        return group

    def _create_group_error_page(self, *, group_info: VulnGroup) -> GroupErrorPage:
        group: GroupErrorPage = {
            'group_title': group_info['groupTitle'],
            'category': group_info['categoryLocaleKey'],
            'vulns': [],
        }

        request_key = group_info['requestKey']
        request_key = cast(str, request_key)

        count = group_info['count']

        if count == 1:
            group['vulns'].append(
                self._convert_error_page(vuln=group_info['vulnerability'])
            )
        else:
            group['vulns'].extend(self._read_error_page_vulns(request_key=request_key))
        return group

    def _create_group_cve(self, *, group_info: VulnGroup) -> GroupCve:
        group: GroupCve = {
            'category': group_info['categoryLocaleKey'],
            'group_title': group_info['groupTitle'],
            'vulns': [],
        }

        request_key = group_info['requestKey']
        request_key = cast(str, request_key)

        count = group_info['count']

        if count == 1:
            group['vulns'].append(self._convert_cve(vuln=group_info['vulnerability']))
        else:
            group['vulns'].extend(self._read_cve_vulns(request_key=request_key))
        return group

    def _convert_issue(self, *, vuln: VulnCommon) -> VulnIssue:
        v: VulnIssue = {
            'url': vuln['urlFull'],
        }
        return v

    def _convert_error_page(self, *, vuln: VulnCommon) -> VulnErrorPage:
        v: VulnErrorPage = {
            'url': vuln['url'],
        }
        return v

    def _convert_cve(self, *, vuln: VulnCommon) -> VulnCve:
        v: VulnCve = {
            'cve_id': vuln['cveId'],
            'vector': vuln['cvssVector'],
        }
        return v

    def _read_issue_vulns(self, *, request_key: str, severity: str) -> List[VulnIssue]:
        vulns = self._read_all_vulns(
            issue_type='issue',
            request_key=request_key,
            severity=severity,
        )

        return [self._convert_issue(vuln=v) for v in vulns]

    def _read_error_page_vulns(self, *, request_key: str) -> List[VulnErrorPage]:
        vulns = self._read_all_vulns(
            issue_type='error_page',
            request_key=request_key,
            severity='info',
        )

        return [self._convert_error_page(vuln=v) for v in vulns]

    def _read_cve_vulns(self, *, request_key: str) -> List[VulnCve]:
        vulns = self._read_all_vulns(
            issue_type='cve',
            request_key=request_key,
            severity='info',
        )

        return [self._convert_cve(vuln=v) for v in vulns]

    @ensure_attrs_set('_site_uuid', '_scan_id')
    def _read_all_vulns(
        self, *, issue_type: str, request_key: str, severity: str
    ) -> List[VulnCommon]:
        """
        Just wrapper for reading all vulns
        """
        vulns: List[VulnCommon] = []
        has_next_page = True
        page = 1  # page starts with 1
        while has_next_page is True:
            vuln_page = self._api.get_vuln_group_page(
                site_uuid=self._site_uuid,
                scan_id=self._scan_id,
                issue_type=issue_type,
                request_key=request_key,
                severity=severity,
                limit=PAGE_VULNS_LIMIT,
                page=page,
            )
            vulns.extend(vuln_page['items'])
            has_next_page = vuln_page['totalCount'] > vuln_page['currentPage']
            page += 1

        return vulns

    def _get_new_profile_uuid(
        self, *, current_settings: SiteSettings, profile_uuid: Optional[str]
    ) -> str:
        if profile_uuid is None:
            profile_uuid = current_settings['profile']['uuid']
        return profile_uuid

    def _get_new_auth_uuid(
        self, *, current_settings: SiteSettings, auth_uuid: Optional[str]
    ) -> Optional[str]:
        if auth_uuid is None and current_settings['authentication'] is not None:
            auth_uuid = current_settings['authentication']['uuid']
        elif auth_uuid == RESET_AUTH_PROFILE:
            auth_uuid = None
        return auth_uuid

    def _get_new_api_profile_uuid(
        self,
        *,
        current_settings: SiteSettings,
        api_profile_uuid: Optional[str] = None,
    ) -> Optional[str]:
        if api_profile_uuid is None and current_settings['apiProfile'] is not None:
            api_profile_uuid = current_settings['apiProfile']['uuid']
        elif api_profile_uuid == RESET_API_PROFILE:
            api_profile_uuid = None
        return api_profile_uuid

    def _is_scan_profile_changed(
        self, *, current_scan_profile: ScanProfile, new_profile_uuid: str
    ) -> bool:
        return current_scan_profile['uuid'] != new_profile_uuid

    def _is_auth_profile_changed(
        self,
        *,
        current_auth_profile: Optional[AuthenticationProfile],
        new_auth_uuid: Optional[str],
    ) -> bool:
        return (
            current_auth_profile is not None
            and new_auth_uuid != current_auth_profile['uuid']
            or current_auth_profile is None
            and new_auth_uuid is not None
        )

    def _is_api_profile_changed(
        self,
        *,
        current_api_profile: Optional[APIProfile],
        new_api_uuid: Optional[str],
    ) -> bool:
        return (
            current_api_profile is not None
            and new_api_uuid != current_api_profile['uuid']
            or current_api_profile is None
            and new_api_uuid is not None
        )

    def _is_settings_changed(
        self,
        *,
        current_settings: SiteSettings,
        new_profile_uuid: str,
        new_auth_uuid: Optional[str],
        new_api_profile_uuid: Optional[str],
    ) -> bool:
        return (
            self._is_scan_profile_changed(
                current_scan_profile=current_settings['profile'],
                new_profile_uuid=new_profile_uuid,
            )
            or self._is_auth_profile_changed(
                current_auth_profile=current_settings['authentication'],
                new_auth_uuid=new_auth_uuid,
            )
            or self._is_api_profile_changed(
                current_api_profile=current_settings['apiProfile'],
                new_api_uuid=new_api_profile_uuid,
            )
        )

    @staticmethod
    def _convert_error_json(*, error: BlackBoxError) -> ErrorReport:
        error_report: ErrorReport
        if isinstance(error, BlackBoxHTTPError):
            error_report = {
                'short_info': 'BlackBox API call failed',
                'message': str(error),
                'json': None,
            }
            if (
                isinstance(error.response, requests.Response)
                and error.response.headers['Content-Type'] == 'application/json'
            ):
                error_report['json'] = error.response.json()
        elif isinstance(error, BlackBoxUrlError):
            error_report = {
                'short_info': 'Invalid BlackBox url or server connection failed',
                'message': str(error),
                'json': None,
            }
        else:
            error_report = {
                'short_info': 'BlackBox error',
                'message': str(error),
                'json': None,
            }

        return error_report

    def _convert_auth_json(
        self, *, raw_auth_data: Dict[str, str], auth_type: AuthenticationType
    ) -> Authentication:
        _converters: Dict[AuthenticationType, Callable[..., Authentication]] = {
            AuthenticationType.HTTP_BASIC: self._convert_http_basic_auth_json,
            AuthenticationType.HTML_AUTO_FORM: self._convert_html_auto_form_auth_json,
            AuthenticationType.HTML_FORM_BASED: self._convert_html_form_based_auth_json,
            AuthenticationType.RAW_COOKIE: self._convert_raw_cookie_auth_json,
            AuthenticationType.API_KEY: self._convert_api_key_auth_json,
            AuthenticationType.BEARER: self._convert_bearer_auth_json,
        }
        return _converters[auth_type](raw_auth_data=raw_auth_data)

    def _pop_auth_type_from_raw_data(
        self, *, raw_auth_data: Dict[str, str]
    ) -> AuthenticationType:
        auth_type = raw_auth_data.pop(AUTH_TYPE_KEY, None)
        if not auth_type:
            raise BlackBoxError('authentication type should be provided')
        elif auth_type not in list(AuthenticationType):
            raise BlackBoxError('unknown authentication type')
        return AuthenticationType(auth_type)

    def _convert_http_basic_auth_json(
        self, *, raw_auth_data: Dict[str, str]
    ) -> HttpBasic:
        username = raw_auth_data.pop(AUTH_USERNAME_KEY, '')
        password = raw_auth_data.pop(AUTH_PASSWORD_KEY, '')
        if not username or not password:
            raise BlackBoxError('username and password should be provided')
        auth_json: HttpBasic = {
            'username': username,
            'password': password,
        }
        return auth_json

    def _convert_html_auto_form_auth_json(
        self, *, raw_auth_data: Dict[str, str]
    ) -> HtmlAutoForm:
        username = raw_auth_data.pop(AUTH_USERNAME_KEY, '')
        password = raw_auth_data.pop(AUTH_PASSWORD_KEY, '')
        form_url = raw_auth_data.pop(AUTH_FORM_URL_KEY, '')
        success_string = raw_auth_data.pop(AUTH_SUCCESS_STRING_KEY, '')
        if not all(
            (
                username,
                password,
                form_url,
                success_string,
            )
        ):
            raise BlackBoxError(
                'username, password, form url and success string should be provided'
            )
        auth_json: HtmlAutoForm = {
            'username': username,
            'password': password,
            'formUrl': form_url,
            'successString': success_string,
        }
        return auth_json

    def _convert_html_form_based_auth_json(
        self, *, raw_auth_data: Dict[str, str]
    ) -> HtmlFormBased:
        form_url = raw_auth_data.pop(AUTH_FORM_URL_KEY, '')
        form_xpath = raw_auth_data.pop(AUTH_FORM_X_PATH_KEY, '')
        username_field = raw_auth_data.pop(AUTH_USERNAME_FIELD_KEY, '')
        username_value = raw_auth_data.pop(AUTH_USERNAME_KEY, '')
        password_field = raw_auth_data.pop(AUTH_PASSWORD_FIELD_KEY, '')
        password_value = raw_auth_data.pop(AUTH_PASSWORD_KEY, '')
        regexp_of_success = raw_auth_data.pop(AUTH_REGEXP_OF_SUCCESS_KEY, '')
        submit_value = raw_auth_data.pop(AUTH_SUBMIT_VALUE_KEY, None)
        if not all(
            (
                form_url,
                form_xpath,
                username_field,
                username_value,
                password_field,
                password_value,
                regexp_of_success,
            )
        ):
            raise BlackBoxError(
                'form url, form xpath, username field, username value, password field, '
                'password value and regexp of success string should be provided'
            )
        auth_json: HtmlFormBased = {
            'formUrl': form_url,
            'formXPath': form_xpath,
            'usernameField': username_field,
            'usernameValue': username_value,
            'passwordField': password_field,
            'passwordValue': password_value,
            'regexpOfSuccess': regexp_of_success,
            'submitValue': submit_value,
        }
        return auth_json

    def _convert_raw_cookie_auth_json(
        self, *, raw_auth_data: Dict[str, str]
    ) -> RawCookie:
        cookies = raw_auth_data.pop(AUTH_COOKIES_KEY, '')
        success_url = raw_auth_data.pop(AUTH_SUCCESS_URL_KEY, '')
        regexp_of_success = raw_auth_data.pop(AUTH_REGEXP_OF_SUCCESS_KEY, '')
        if not all(
            (
                cookies,
                success_url,
                regexp_of_success,
            )
        ):
            raise BlackBoxError(
                'cookies, success url and regexp of success should be provided'
            )
        auth_json: RawCookie = {
            'cookies': cookies.rstrip(';').split(';'),
            'successUrl': success_url,
            'regexpOfSuccess': regexp_of_success,
        }
        return auth_json

    def _convert_api_key_auth_json(self, *, raw_auth_data: Dict[str, str]) -> ApiKey:
        place = raw_auth_data.pop(AUTH_APIKEY_PLACE_KEY, '')
        name = raw_auth_data.pop(AUTH_APIKEY_NAME_KEY, '')
        value = raw_auth_data.pop(AUTH_APIKEY_VALUE_KEY, '')
        success_url = raw_auth_data.pop(AUTH_SUCCESS_URL_KEY, '')
        success_string = raw_auth_data.pop(AUTH_SUCCESS_STRING_KEY, None)
        if not all(
            (
                place,
                name,
                value,
                success_url,
            )
        ):
            raise BlackBoxError('place, name, value and success url should be provided')
        elif place not in list(ApiKeyPlace):
            verbose = ', '.join(ApiKeyPlace)
            raise BlackBoxError(f'place can be one of: {verbose}')
        auth_json: ApiKey = {
            'place': ApiKeyPlace(place),
            'name': name,
            'value': value,
            'successUrl': success_url,
            'successString': success_string,
        }
        return auth_json

    def _convert_bearer_auth_json(self, *, raw_auth_data: Dict[str, str]) -> Bearer:
        token = raw_auth_data.pop(AUTH_TOKEN_KEY, '')
        success_url = raw_auth_data.pop(AUTH_SUCCESS_URL_KEY, '')
        success_string = raw_auth_data.pop(AUTH_SUCCESS_STRING_KEY, None)
        if not all(
            (
                token,
                success_url,
            )
        ):
            raise BlackBoxError('token and success url should be provided')
        auth_json: Bearer = {
            'token': token,
            'successUrl': success_url,
            'successString': success_string,
        }
        return auth_json

    @property
    def _scan_url(self) -> str:
        return urllib.parse.urljoin(
            self._ui_base_url,
            f'/sites/{self._site_uuid}/scans/{self._scan_id}',
        )
