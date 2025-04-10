from typing import Tuple

from blackbox_ci.types import ReportHTMLTemplate, ReportTemplateShortname, ScanStatus

# transport consts
SERVER_RETRY_MAX_ATTEMPTS = 5
SERVER_RETRY_BACKOFF_FACTOR = 0.5
SERVER_RETRY_STATUSES = (502, 503, 504)

# exit codes
SUCCESS_EXIT_CODE = 0
ERROR_EXIT_CODE = 1
SCORE_FAIL_EXIT_CODE = 3

# settings consts
RESET_AUTH_PROFILE = 'RESET'
RESET_API_PROFILE = 'RESET'

# url consts
STANDARD_PORT_SCHEMES = {
    80: 'http',
    443: 'https',
}
DEFAULT_SCHEME = 'https'

# scan status consts
IDLE_SCAN_STATUSES: Tuple[ScanStatus, ...] = (ScanStatus.stopped, ScanStatus.finished)

# vulns consts
PAGE_VULNS_LIMIT = 100

# report consts
HTML_TEMPLATES_MAP = {
    ReportTemplateShortname.HTML: ReportHTMLTemplate.PLAIN,
    ReportTemplateShortname.NIST: ReportHTMLTemplate.NIST,
    ReportTemplateShortname.OUD4: ReportHTMLTemplate.OUD4,
    ReportTemplateShortname.OWASP: ReportHTMLTemplate.OWASP,
    ReportTemplateShortname.OWASP_MOBILE: ReportHTMLTemplate.OWASP_MOBILE,
    ReportTemplateShortname.PCIDSS: ReportHTMLTemplate.PCIDSS,
    ReportTemplateShortname.SANS: ReportHTMLTemplate.SANS,
}
REPORT_FILENAME_DATETIME_FORMAT = '%Y%m%d_%H%M%S'

# option consts
BLACKBOX_URL_OPTION = '--blackbox-url'
BLACKBOX_URL_ENV = 'BLACKBOX_URL'
BLACKBOX_API_TOKEN_OPTION = '--blackbox-api-token'  # noqa: S105
BLACKBOX_API_TOKEN_ENV = 'BLACKBOX_API_TOKEN'  # noqa: S105
TARGET_URL_OPTION = '--target-url'
TARGET_URL_ENV = 'TARGET_URL'
TARGET_UUID_OPTION = '--target-uuid'
TARGET_UUID_ENV = 'TARGET_UUID'
TARGET_FILE_OPTION = '--target-file'
TARGET_FILE_ENV = 'TARGET_FILE'
GROUP_UUID_OPTION = '--group-uuid'
GROUP_UUID_ENV = 'GROUP_UUID'
IGNORE_SSL_OPTION = '--ignore-ssl'
IGNORE_SSL_ENV = 'IGNORE_SSL'
AUTO_CREATE_OPTION = '--auto-create'
PREVIOUS_OPTION = '--previous'
NO_WAIT_OPTION = '--no-wait'
SHARED_LINK_OPTION = '--shared-link'
SCAN_PROFILE_OPTION = '--scan-profile'
SCAN_PROFILE_ENV = 'SCAN_PROFILE'
AUTH_DATA_OPTION = '--auth-data'
AUTH_PASSWORD_ENV = 'AUTH_PASSWORD'  # noqa: S105
AUTH_TOKEN_ENV = 'AUTH_TOKEN'  # noqa: S105
AUTH_API_KEY_VALUE_ENV = 'AUTH_API_KEY_VALUE'
AUTH_PROFILE_OPTION = '--auth-profile'
AUTH_PROFILE_ENV = 'AUTH_PROFILE'
API_SCHEMA_OPTION = '--api-schema'
API_SCHEMA_ENV = 'API_SCHEMA'
FAIL_UNDER_SCORE_OPTION = '--fail-under-score'
REPORT_DIR_OPTION = '--report-dir'
REPORT_TEMPLATE_OPTION = '--report-template'
REPORT_LOCALE_OPTION = '--report-locale'
RESULTS_ONLY_OPTION = '--results-only'
SCAN_UUID_OPTION = '--scan-uuid'
SCAN_UUID_OPTION_ALIAS = '--scan-id'

# auth file keys
AUTH_TYPE_KEY = 'TYPE'
AUTH_USERNAME_KEY = 'USERNAME'
AUTH_PASSWORD_KEY = 'PASSWORD'  # noqa: S105
AUTH_FORM_URL_KEY = 'FORM_URL'
AUTH_SUCCESS_STRING_KEY = 'SUCCESS_STRING'
AUTH_FORM_X_PATH_KEY = 'FORM_X_PATH'
AUTH_USERNAME_FIELD_KEY = 'USERNAME_FIELD'
AUTH_PASSWORD_FIELD_KEY = 'PASSWORD_FIELD'  # noqa: S105
AUTH_REGEXP_OF_SUCCESS_KEY = 'REGEXP_OF_SUCCESS'
AUTH_SUBMIT_VALUE_KEY = 'SUBMIT_VALUE'
AUTH_COOKIES_KEY = 'COOKIES'
AUTH_SUCCESS_URL_KEY = 'SUCCESS_URL'
AUTH_APIKEY_PLACE_KEY = 'PLACE'
AUTH_APIKEY_NAME_KEY = 'NAME'
AUTH_APIKEY_VALUE_KEY = 'VALUE'
AUTH_TOKEN_KEY = 'TOKEN'  # noqa: S105
