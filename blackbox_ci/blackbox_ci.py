import json
import logging
import sys
import time
import warnings
from typing import Any, Callable, Dict, List, Optional, TextIO

import click
import urllib3.exceptions
from requests.adapters import HTTPAdapter, Retry

from blackbox_ci.blackbox_api import BlackBoxAPI
from blackbox_ci.blackbox_operator import BlackBoxOperator
from blackbox_ci.consts import (
    API_SCHEMA_ENV,
    API_SCHEMA_OPTION,
    AUTH_API_KEY_VALUE_ENV,
    AUTH_DATA_OPTION,
    AUTH_PASSWORD_ENV,
    AUTH_PROFILE_ENV,
    AUTH_PROFILE_OPTION,
    AUTH_TOKEN_ENV,
    AUTO_CREATE_OPTION,
    BLACKBOX_API_TOKEN_ENV,
    BLACKBOX_API_TOKEN_OPTION,
    BLACKBOX_URL_ENV,
    BLACKBOX_URL_OPTION,
    ERROR_EXIT_CODE,
    FAIL_UNDER_SCORE_OPTION,
    GROUP_UUID_ENV,
    GROUP_UUID_OPTION,
    IGNORE_SSL_ENV,
    IGNORE_SSL_OPTION,
    NO_WAIT_OPTION,
    PREVIOUS_OPTION,
    REPORT_DIR_OPTION,
    REPORT_LOCALE_OPTION,
    REPORT_TEMPLATE_OPTION,
    RESET_API_PROFILE,
    RESET_AUTH_PROFILE,
    RESULTS_ONLY_OPTION,
    SCAN_PROFILE_ENV,
    SCAN_PROFILE_OPTION,
    SCAN_UUID_OPTION,
    SCAN_UUID_OPTION_ALIAS,
    SCORE_FAIL_EXIT_CODE,
    SERVER_RETRY_BACKOFF_FACTOR,
    SERVER_RETRY_MAX_ATTEMPTS,
    SERVER_RETRY_STATUSES,
    SHARED_LINK_OPTION,
    SUCCESS_EXIT_CODE,
    TARGET_FILE_ENV,
    TARGET_FILE_OPTION,
    TARGET_URL_ENV,
    TARGET_URL_OPTION,
    TARGET_UUID_ENV,
    TARGET_UUID_OPTION,
)
from blackbox_ci.errors import (
    BlackBoxError,
    BlackBoxInitError,
    ScanFailedError,
    ScoreFailError,
)
from blackbox_ci.files import read_key_value_pairs
from blackbox_ci.options import (
    EnumChoice,
    check_auth_options,
    check_report_output_options,
    check_target_source,
    update_auth_data_on_env,
)
from blackbox_ci.types import (
    ErrorReport,
    ReportLocale,
    ReportTemplateShortname,
    ScanReport,
)


def collect_scan_report(
    *,
    operator: BlackBoxOperator,
    target_url: Optional[str],
    target_uuid: Optional[str],
    auto_create: bool,
    shared_link: bool,
    group_uuid: Optional[str],
    report_dir: Optional[str],
    report_template: ReportTemplateShortname,
    report_locale: ReportLocale,
    scan_uuid: Optional[str],
    **_: Any,
) -> ScanReport:
    operator.set_target(
        url=target_url, uuid=target_uuid, group_uuid=group_uuid, auto_create=auto_create
    )
    operator.set_scan(scan_uuid=scan_uuid)
    report_path: Optional[str] = (
        operator.generate_report_file(
            locale=report_locale,
            template_shortname=report_template,
            output_dir=report_dir,
        )
        if report_dir is not None
        else None
    )
    report: ScanReport = operator.get_scan_report(
        target_url=target_url,
        shared_link=shared_link,
        report_path=report_path,
        partial_results=True,
    )
    return report


def run_target_scan(
    *,
    operator: BlackBoxOperator,
    target_url: Optional[str],
    target_uuid: Optional[str],
    auto_create: bool,
    previous: str,
    skip_wait_step: bool,
    shared_link: bool,
    scan_profile_uuid: Optional[str],
    auth_profile_uuid: Optional[str],
    api_profile_uuid: Optional[str],
    group_uuid: Optional[str],
    report_dir: Optional[str],
    report_template: ReportTemplateShortname,
    report_locale: ReportLocale,
    auth_data: Dict[str, str],
    **_: Any,
) -> ScanReport:
    operator.set_target(
        url=target_url, uuid=target_uuid, group_uuid=group_uuid, auto_create=auto_create
    )

    operator.ensure_target_is_idle(previous=previous)
    if auth_data:
        # for multiple targets from the same group create auth profile only once
        auth_profile_uuid = auth_data.get('uuid') or operator.create_auth_profile(
            auth_data=auth_data
        )
        auth_data['uuid'] = auth_profile_uuid

    if any((scan_profile_uuid, auth_profile_uuid, api_profile_uuid)):
        operator.set_site_settings(
            profile_uuid=scan_profile_uuid,
            auth_uuid=auth_profile_uuid,
            api_profile_uuid=api_profile_uuid,
        )

    operator.start_scan()
    report_path: Optional[str] = None
    if not skip_wait_step:
        operator.wait_for_scan()
        if report_dir is not None:
            report_path = operator.generate_report_file(
                locale=report_locale,
                template_shortname=report_template,
                output_dir=report_dir,
            )
    report: ScanReport = operator.get_scan_report(
        target_url=target_url, shared_link=shared_link, report_path=report_path
    )
    return report


def handle_scan_target(
    *,
    handler: Callable[..., ScanReport],
    target_url: Optional[str],
    target_uuid: Optional[str],
    blackbox_url: str,
    blackbox_api_token: str,
    ignore_ssl: bool,
    shared_link: bool,
    **kwargs: Any,
) -> ScanReport:
    try:
        retry = Retry(
            total=SERVER_RETRY_MAX_ATTEMPTS,
            status_forcelist=SERVER_RETRY_STATUSES,
            backoff_factor=SERVER_RETRY_BACKOFF_FACTOR,
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        api = BlackBoxAPI(
            base_url=blackbox_url,
            api_token=blackbox_api_token,
            ignore_ssl=ignore_ssl,
            adapter=adapter,
        )
        operator = BlackBoxOperator(url=blackbox_url, api=api)
    except BlackBoxInitError as err:
        return BlackBoxOperator.get_init_error_report(
            target_url=target_url,
            target_uuid=target_uuid,
            report_path=None,
            error=err,
        )

    try:
        return handler(
            operator=operator,
            target_url=target_url,
            target_uuid=target_uuid,
            shared_link=shared_link,
            **kwargs,
        )
    except BlackBoxError as err:
        return operator.get_error_report(
            target_url=target_url,
            target_uuid=target_uuid,
            report_path=None,
            shared_link=shared_link,
            error=err,
        )


def check_errors(failed_targets: List[str]) -> None:
    if failed_targets:
        failed_targets_message = '"\n"'.join(failed_targets)
        logging.error(
            f'errors occurred for targets:\n"{failed_targets_message}"\n'
            f'See error log above'
        )
        raise ScanFailedError()


def check_reports(
    reports: List[ScanReport],
    fail_under_score: Optional[float],
) -> None:
    if fail_under_score is not None:
        for report in reports:
            if report['score'] is not None and report['score'] < fail_under_score:
                raise ScoreFailError()


def log_current_target(target_list: List[str], target: str) -> None:
    count = target_list.count(target)
    if count > 1:
        logging.warning(f'Target {target} is repeated in list {count} times')
    logging.info(f'Starting scan for target `{target}`')


def log_report_errors(errors: List[ErrorReport]) -> None:
    for err in errors:
        short_info = err['short_info']
        message = err['message']
        verbose = ''
        if err['json']:
            verbose = json.dumps(err['json'], indent=2)
            verbose = f'\n{verbose}'
        logging.error(f'{short_info}: {message}{verbose}')


def process_target_list(
    *,
    target_list: List[str],
    fail_under_score: Optional[float],
    auth_data: Optional[TextIO],
    **kwargs: Any,
) -> None:
    common_auth_profile_data = (
        read_key_value_pairs(auth_data, on_env_updater=update_auth_data_on_env)
        if auth_data
        else None
    )
    reports = []
    failed_targets = []
    unique_targets = set(target_list)
    for target in unique_targets:
        log_current_target(target_list, target)

        report = handle_scan_target(
            auth_data=common_auth_profile_data,
            target_url=target,
            target_uuid=None,
            **kwargs,
        )
        errors = report['errors']
        if errors:
            log_report_errors(errors)
            failed_targets.append(target)
        reports.append(report)
        time.sleep(3.0)

    print(json.dumps(reports))
    check_errors(failed_targets)
    check_reports(reports, fail_under_score)


def process_single_target(
    *,
    fail_under_score: Optional[float],
    auth_data: Optional[TextIO],
    **kwargs: Any,
) -> None:
    auth_profile_data = (
        read_key_value_pairs(auth_data, on_env_updater=update_auth_data_on_env)
        if auth_data
        else None
    )
    report = handle_scan_target(auth_data=auth_profile_data, **kwargs)
    errors = report['errors']
    if errors:
        log_report_errors(errors)

    print(json.dumps(report))

    if errors:
        raise ScanFailedError()
    elif (
        report['score'] is not None
        and fail_under_score is not None
        and report['score'] < fail_under_score
    ):
        raise ScoreFailError()


@click.command()
@click.option(
    BLACKBOX_URL_OPTION, envvar=BLACKBOX_URL_ENV, default='https://bbs.ptsecurity.com/'
)
@click.option(BLACKBOX_API_TOKEN_OPTION, envvar=BLACKBOX_API_TOKEN_ENV, required=True)
@click.option(
    TARGET_URL_OPTION,
    envvar=TARGET_URL_ENV,
    default=None,
    help=f'Set url of scan target. '
    f'Do not use with {TARGET_FILE_OPTION}, {TARGET_UUID_OPTION}.',
)
@click.option(
    TARGET_FILE_OPTION,
    envvar=TARGET_FILE_ENV,
    type=click.File('r'),
    default=None,
    help=f'Set filename with target urls. '
    f'Do not use with {TARGET_URL_OPTION}, {TARGET_UUID_OPTION}.',
)
@click.option(
    TARGET_UUID_OPTION,
    envvar=TARGET_UUID_ENV,
    default=None,
    help=f'Set uuid of scan target. '
    f'Do not use with {TARGET_URL_OPTION}, {TARGET_FILE_OPTION}.',
)
@click.option(
    GROUP_UUID_OPTION,
    envvar=GROUP_UUID_ENV,
    help='Set group UUID for site',
    default=None,
)
@click.option(
    IGNORE_SSL_OPTION,
    envvar=IGNORE_SSL_ENV,
    is_flag=True,
    default=False,
    help='Skip verification of BlackBox API host certificate.',
)
@click.option(
    AUTO_CREATE_OPTION,
    is_flag=True,
    help='Automatically create a site if a site with the target URL '
    'in the specified group was not found.',
)
@click.option(
    PREVIOUS_OPTION,
    type=click.Choice(['wait', 'stop', 'fail']),
    default='fail',
    help='What to do if the target is currently being scanned.',
)
@click.option(
    NO_WAIT_OPTION,
    is_flag=True,
    help='Do not wait until the started scan is finished.',
)
@click.option(
    SHARED_LINK_OPTION,
    is_flag=True,
    default=False,
    help='Create shared link for scan.',
)
@click.option(
    SCAN_PROFILE_OPTION,
    'scan_profile_uuid',
    envvar=SCAN_PROFILE_ENV,
    help='Set scan profile UUID for new scan',
)
@click.option(
    AUTH_PROFILE_OPTION,
    'auth_profile_uuid',
    envvar=AUTH_PROFILE_ENV,
    help='Set authentication profile UUID for site. '
    f'Cannot be used with {AUTH_DATA_OPTION} option. '
    f'For scanning without authentication specify `{RESET_AUTH_PROFILE}` in the option',
)
@click.option(
    API_SCHEMA_OPTION,
    'api_profile_uuid',
    envvar=API_SCHEMA_ENV,
    help='Set API-schema UUID for site. '
    f'For scanning without API-schema specify `{RESET_API_PROFILE}` in the option',
)
@click.option(
    FAIL_UNDER_SCORE_OPTION,
    type=click.FloatRange(1, 10),
    default=None,
    help='Fail with exit code 3 if report scoring is less '
    'than given score (set "1" or do not set to never fail).',
)
@click.option(
    REPORT_DIR_OPTION,
    type=click.Path(
        exists=True, resolve_path=True, file_okay=False, dir_okay=True, writable=True
    ),
    default=None,
    help='Set directory path for storing the generated report file. '
    'If the option is used, the report will be saved in the specified directory. '
    f'Cannot be used with {NO_WAIT_OPTION} option. '
    'To generate a report the scan must be finished or stopped.',
)
@click.option(
    REPORT_TEMPLATE_OPTION,
    type=EnumChoice(ReportTemplateShortname, case_sensitive=False, use_value=True),
    default=ReportTemplateShortname.HTML,
    help='Template shortname of the report to be generated. '
    f'Specifies file format for report in {REPORT_DIR_OPTION}.',
)
@click.option(
    REPORT_LOCALE_OPTION,
    type=EnumChoice(ReportLocale, case_sensitive=False, use_value=True),
    default=ReportLocale.RU,
    help='Localization of the report file to be generated. '
    f'Specifies file localization for report in {REPORT_DIR_OPTION}.',
)
@click.option(
    RESULTS_ONLY_OPTION,
    is_flag=True,
    help='Only get results of specified site. '
    'Last scan results by default. '
    f'Use {SCAN_UUID_OPTION} option to get results of specific scan.',
)
@click.option(
    SCAN_UUID_OPTION,
    SCAN_UUID_OPTION_ALIAS,
    default=None,
    help='Set the scan UUID to get the results. '
    f'Can be used without {RESULTS_ONLY_OPTION} option.',
)
@click.option(
    AUTH_DATA_OPTION,
    type=click.File('r'),
    default=None,
    help='Set path to file with authentication data. '
    'If this option is used, a new authentication profile '
    'with the data provided will be created and used for new scan. '
    f'Cannot be used with {AUTH_PROFILE_OPTION} option. '
    'It is highly recommended to use environment variables '
    'to store passwords, tokens and api keys: '
    f'{AUTH_PASSWORD_ENV}, {AUTH_TOKEN_ENV}, {AUTH_API_KEY_VALUE_ENV}',
)
def run_command(
    blackbox_url: str,
    blackbox_api_token: str,
    target_url: Optional[str],
    target_file: Optional[TextIO],
    target_uuid: Optional[str],
    ignore_ssl: bool,
    auto_create: bool,
    previous: str,
    no_wait: bool,
    shared_link: bool,
    scan_profile_uuid: Optional[str],
    auth_profile_uuid: Optional[str],
    api_profile_uuid: Optional[str],
    fail_under_score: Optional[float],
    group_uuid: Optional[str],
    report_dir: Optional[str],
    report_template: ReportTemplateShortname,
    report_locale: ReportLocale,
    results_only: bool,
    scan_uuid: Optional[str],
    auth_data: Optional[TextIO],
) -> None:
    check_target_source(
        target_url=target_url,
        target_file=target_file,
        target_uuid=target_uuid,
        auto_create=auto_create,
    )
    check_report_output_options(
        report_dir=report_dir,
        no_wait=no_wait,
        scan_uuid=scan_uuid,
        results_only=results_only,
    )
    check_auth_options(
        auth_profile_uuid=auth_profile_uuid,
        auth_data=auth_data,
        scan_uuid=scan_uuid,
        results_only=results_only,
    )

    if ignore_ssl:
        warnings.simplefilter('ignore', urllib3.exceptions.InsecureRequestWarning)

    handler: Callable[..., ScanReport]
    if results_only or scan_uuid:
        handler = collect_scan_report
    else:
        handler = run_target_scan

    if target_file:
        target_list = target_file.read().splitlines()
        process_target_list(
            handler=handler,
            blackbox_url=blackbox_url,
            blackbox_api_token=blackbox_api_token,
            target_list=target_list,
            ignore_ssl=ignore_ssl,
            auto_create=auto_create,
            previous=previous,
            skip_wait_step=no_wait,
            shared_link=shared_link,
            scan_profile_uuid=scan_profile_uuid,
            auth_profile_uuid=auth_profile_uuid,
            api_profile_uuid=api_profile_uuid,
            fail_under_score=fail_under_score,
            group_uuid=group_uuid,
            report_dir=report_dir,
            report_template=report_template,
            report_locale=report_locale,
            results_only=results_only,
            scan_uuid=scan_uuid,
            auth_data=auth_data,
        )
    elif target_url or target_uuid:
        process_single_target(
            handler=handler,
            blackbox_url=blackbox_url,
            blackbox_api_token=blackbox_api_token,
            target_url=target_url,
            target_uuid=target_uuid,
            ignore_ssl=ignore_ssl,
            auto_create=auto_create,
            previous=previous,
            skip_wait_step=no_wait,
            shared_link=shared_link,
            scan_profile_uuid=scan_profile_uuid,
            auth_profile_uuid=auth_profile_uuid,
            api_profile_uuid=api_profile_uuid,
            fail_under_score=fail_under_score,
            group_uuid=group_uuid,
            report_dir=report_dir,
            report_template=report_template,
            report_locale=report_locale,
            results_only=results_only,
            scan_uuid=scan_uuid,
            auth_data=auth_data,
        )


def main() -> None:  # noqa: C901
    logging.basicConfig(
        level=logging.DEBUG, format='%(asctime)s %(levelname)s [%(name)s] %(message)s'
    )
    try:
        run_command()
    except ScanFailedError:
        sys.exit(ERROR_EXIT_CODE)
    except ScoreFailError:
        sys.exit(SCORE_FAIL_EXIT_CODE)
    sys.exit(SUCCESS_EXIT_CODE)
