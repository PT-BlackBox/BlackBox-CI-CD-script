import urllib.parse
from typing import Any, List, Optional, cast
from http import HTTPStatus

import requests
from requests.adapters import HTTPAdapter

from blackbox_ci.errors import (
    BlackBoxConnectionError,
    BlackBoxError,
    BlackBoxHTTPError,
    BlackBoxInvalidUrlError,
    BlackBoxRequestError,
    BlackBoxSSLError,
)
from blackbox_ci.types import (
    Authentication,
    ReportHTMLTemplate,
    ReportLocale,
    Scan,
    Site,
    SiteSettings,
    UserGroupInfo,
    VulnGroup,
    VulnPage,
)


class BlackBoxAPI:
    def __init__(
        self, *, base_url: str, api_token: str, ignore_ssl: bool, adapter: HTTPAdapter
    ) -> None:
        self._sess = requests.session()
        self._sess.mount('http://', adapter)
        self._sess.mount('https://', adapter)
        self._sess.verify = not ignore_ssl
        self._test_base_url(base_url)
        self._api_service_url = urllib.parse.urljoin(base_url, 'app/api/v1/')
        self._sess.hooks['response'] = [
            self._raise_for_status,
            self._ensure_json,
        ]
        self._sess.headers['Authorization'] = f'Basic {api_token}'

    def get_groups(self) -> List[UserGroupInfo]:
        groups_url = urllib.parse.urljoin(self._api_service_url, 'groups')
        resp = self._get(groups_url)
        return cast(List[UserGroupInfo], resp.json())

    def get_group(self, *, group_uuid: str) -> UserGroupInfo:
        group_url = urllib.parse.urljoin(self._api_service_url, f'groups/{group_uuid}')
        resp = self._get(group_url)
        return cast(UserGroupInfo, resp.json())

    def get_sites(self) -> List[Site]:
        sites_url = urllib.parse.urljoin(self._api_service_url, 'sites')
        resp = self._get(sites_url)
        return cast(List[Site], resp.json())

    def get_site(self, *, site_uuid: str) -> Site:
        sites_url = urllib.parse.urljoin(self._api_service_url, f'sites/{site_uuid}')
        resp = self._get(sites_url)
        return cast(Site, resp.json())

    def add_site(self, *, target_url: str, group_uuid: str) -> str:
        sites_url = urllib.parse.urljoin(self._api_service_url, 'sites/add')
        sites_req = {'url': target_url, 'groupUUID': group_uuid}
        resp = self._post(sites_url, json=sites_req)
        site_uuid = resp.json()['uuid']
        return str(site_uuid)

    def set_site_settings(
        self,
        *,
        site_uuid: str,
        profile_uuid: str,
        authentication_uuid: Optional[str],
        api_profile_uuid: Optional[str],
    ) -> None:
        sites_url = urllib.parse.urljoin(
            self._api_service_url, f'sites/{site_uuid}/settings'
        )
        sites_req = {
            'profileUUID': profile_uuid,
            'authenticationUUID': authentication_uuid,
            'apiProfileUUID': api_profile_uuid,
        }
        self._post(sites_url, json=sites_req)

    def get_site_settings(self, *, site_uuid: str) -> SiteSettings:
        sites_url = urllib.parse.urljoin(
            self._api_service_url, f'sites/{site_uuid}/settings'
        )
        resp = self._get(sites_url)
        settings = resp.json()
        return cast(SiteSettings, settings)

    def start_scan(self, *, site_uuid: str) -> int:
        sites_url = urllib.parse.urljoin(
            self._api_service_url, f'sites/{site_uuid}/start'
        )
        resp = self._post(sites_url)
        scan_id = resp.json()['id']
        return int(scan_id)

    def stop_scan(self, *, site_uuid: str) -> None:
        sites_url = urllib.parse.urljoin(
            self._api_service_url, f'sites/{site_uuid}/stop'
        )
        self._post(sites_url)

    def get_scan(self, *, site_uuid: str, scan_id: int) -> Scan:
        scan_url = urllib.parse.urljoin(
            self._api_service_url, f'sites/{site_uuid}/scans/{scan_id}'
        )
        resp = self._get(scan_url)
        scan = resp.json()
        return cast(Scan, scan)

    def get_vuln_group_page(
        self,
        *,
        site_uuid: str,
        scan_id: int,
        issue_type: str,
        request_key: str,
        severity: str,
        limit: int,
        page: int,
    ) -> VulnPage:
        vuln_group_url = urllib.parse.urljoin(
            self._api_service_url,
            f'sites/{site_uuid}/scans/{scan_id}/vulnerabilities'
            f'/{issue_type}/{request_key}/{severity}'
            f'?limit={limit}&page={page}',
        )
        resp = self._get(vuln_group_url)
        return cast(VulnPage, resp.json())

    def get_vuln_groups(self, *, site_uuid: str, scan_id: int) -> List[VulnGroup]:
        vulns_url = urllib.parse.urljoin(
            self._api_service_url, f'sites/{site_uuid}/scans/{scan_id}/vulnerabilities'
        )
        resp = self._get(vulns_url)
        return cast(List[VulnGroup], resp.json())

    def get_score(self, *, site_uuid: str, scan_id: int) -> Optional[float]:
        score_url = urllib.parse.urljoin(
            self._api_service_url, f'sites/{site_uuid}/scans/{scan_id}'
        )
        resp = self._get(score_url)
        score = resp.json()['score']
        return cast(Optional[float], score)

    def create_shared_link(self, *, site_uuid: str, scan_id: int) -> str:
        url = urllib.parse.urljoin(
            self._api_service_url, f'sites/{site_uuid}/scans/{scan_id}/shared'
        )
        resp = self._post(url, json={})
        uuid = resp.json()['uuid']
        return cast(str, uuid)

    def create_auth_profile(
        self,
        *,
        auth_type: str,
        auth_field: str,
        authentication: Authentication,
        group_uuid: str,
        name: str,
    ) -> str:
        url = urllib.parse.urljoin(self._api_service_url, 'auth-profiles')
        authprofiles_req = {
            'name': name,
            'type': auth_type,
            auth_field: authentication,
            'groupUUID': group_uuid,
        }
        resp = self._post(url, json=authprofiles_req)
        uuid = resp.json()['uuid']
        return cast(str, uuid)

    def get_sarif_report_content(
        self, *, site_uuid: str, scan_id: int, locale: ReportLocale
    ) -> bytes:
        url = urllib.parse.urljoin(self._api_service_url, f'reports/sarif/{site_uuid}/{scan_id}')
        params = {
            'locale': locale.value,
        }
        return self._get(
            url, params=params, hooks={'response': [self._raise_for_status]}
        ).content

    def get_html_report_content(
        self,
        *,
        site_uuid: str,
        scan_id: int,
        locale: ReportLocale,
        template: ReportHTMLTemplate,
    ) -> bytes:
        url = urllib.parse.urljoin(self._api_service_url, f'reports/html/{site_uuid}/{scan_id}')
        params = {
            'locale': locale.value,
            'template': template.value,
        }
        return self._get(
            url, params=params, hooks={'response': [self._raise_for_status]}
        ).content

    def _request(
        self,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> requests.Response:
        if method not in ('GET', 'POST'):
            raise RuntimeError(f'Method {method} not allowed')

        try:
            resp = self._sess.request(method, url=url, **kwargs)
        except requests.exceptions.ConnectionError:
            raise BlackBoxConnectionError(f'Failed connection to "{url}"')
        except requests.RequestException as er:
            raise BlackBoxRequestError(f'Error while handling request {er}')
        else:
            return resp

    def _get(self, url: str, **kwargs: Any) -> requests.Response:
        kwargs.setdefault('allow_redirects', True)
        return self._request('GET', url=url, **kwargs)

    def _post(
        self,
        url: str,
        **kwargs: Any,
    ) -> requests.Response:
        return self._request('POST', url=url, **kwargs)

    @staticmethod
    def _raise_for_status(resp: requests.Response, *args: Any, **kwargs: Any) -> None:
        try:
            resp.raise_for_status()
        except requests.HTTPError as er:
            raise BlackBoxHTTPError(er, request=er.request, response=er.response)

    @staticmethod
    def _ensure_json(resp: requests.Response, *args: Any, **kwargs: Any) -> None:
        if resp.status_code == HTTPStatus.NO_CONTENT:
            return
        if resp.headers.get('content-type') != 'application/json':
            raise BlackBoxError(
                'unexpected API response content type, '
                'check if BlackBox URL is specified correctly'
            )

    def _test_base_url(self, url: str) -> None:
        try:
            resp = self._sess.get(url)
        except requests.exceptions.SSLError:
            raise BlackBoxSSLError(
                f'SSL verification failed for "{url}", '
                f'it is possible to ignore SSL verification '
                f'if you trust this server'
            )
        except requests.exceptions.ConnectionError:
            raise BlackBoxConnectionError(f'Failed connection to "{url}"')
        except ValueError:
            raise BlackBoxInvalidUrlError(f'Check url provided "{url}"')
        else:
            self._raise_for_status(resp)
