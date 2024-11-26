from enum import Enum
from typing import (
    Any,
    Callable,
    Dict,
    List,
    NamedTuple,
    Optional,
    TypedDict,
    TypeVar,
)

VulnCommon = Dict[str, Any]


class ScanStatus(str, Enum):
    created = 'created'
    sent_start_task = 'sent_start_task'
    started = 'started'
    sent_stop_task = 'sent_stop_task'
    stopped = 'stopped'
    finished = 'finished'


OnEnvUpdater = Callable[[Dict[str, str]], None]


class VulnGroup(TypedDict):
    issueType: str
    categoryLocaleKey: str
    count: int
    # reflects group name on UI
    groupTitle: str
    requestKey: Optional[str]
    severity: str
    vulnerability: VulnCommon


class VulnPage(TypedDict):
    items: List[VulnCommon]
    totalItems: int
    totalCount: int
    currentPage: int


class VulnIssue(TypedDict):
    """Vuln type: issue"""

    url: str


class VulnErrorPage(TypedDict):
    """Vuln type: error_page"""

    url: str


class VulnCve(TypedDict):
    """Vuln type: cve"""

    cve_id: str
    vector: str


class GroupIssue(TypedDict):
    severity: str
    category: str
    group_title: str
    vulns: List[VulnIssue]


class GroupErrorPage(TypedDict):
    group_title: str
    category: str
    vulns: List[VulnErrorPage]


class GroupCve(TypedDict):
    category: str
    group_title: str
    vulns: List[VulnCve]


class TargetVulns(TypedDict):
    issue_groups: List[GroupIssue]
    cve_groups: List[GroupCve]
    error_page_groups: List[GroupErrorPage]


class ReportScanStatus(str, Enum):
    in_progress = 'in_progress'
    stopped = 'stopped'
    finished = 'finished'


class ErrorReport(TypedDict):
    short_info: str
    message: str
    json: Optional[Dict[Any, Any]]


class ScanReport(TypedDict):
    target_url: Optional[str]
    target_uuid: Optional[str]
    url: Optional[str]
    scan_status: Optional[ReportScanStatus]
    vulns: Optional[TargetVulns]
    sharedLink: Optional[str]
    score: Optional[float]
    report_path: Optional[str]
    errors: Optional[List[ErrorReport]]


class ScanProfile(TypedDict):
    uuid: str
    name: str
    type: str


class AuthenticationProfile(TypedDict):
    uuid: str
    name: str
    type: str


class APIProfile(TypedDict):
    uuid: str
    name: str
    countOfSchemas: int


class SiteSettings(TypedDict):
    url: str
    name: str
    profile: ScanProfile
    authentication: Optional[AuthenticationProfile]
    apiProfile: Optional[APIProfile]


class Scan(TypedDict):
    errorReason: Optional[str]
    id: int
    status: ScanStatus
    progress: int
    profile: ScanProfile
    authentication: Optional[AuthenticationProfile]
    apiProfile: Optional[APIProfile]
    score: float


class SiteGroupInfo(TypedDict):
    uuid: str
    name: str


class Site(TypedDict):
    uuid: str
    url: str
    name: str
    lastScan: Optional[Scan]
    profile: ScanProfile
    authentication: Optional[AuthenticationProfile]
    apiProfile: Optional[APIProfile]
    group: SiteGroupInfo


class UserGroupType(str, Enum):
    PRODUCT = 'product'
    USER = 'user'


class UserGroupInfo(SiteGroupInfo):
    type: str
    role: str


class UrlParts(NamedTuple):
    scheme: str
    hostname: str
    port: Optional[int]
    path: Optional[str]
    query: Optional[str]
    fragment: Optional[str]


class ReportTemplateShortname(str, Enum):
    HTML = 'html'
    NIST = 'nist'
    OUD4 = 'oud4'
    OWASP = 'owasp'
    OWASP_MOBILE = 'owasp_mobile'
    PCIDSS = 'pcidss'
    SARIF = 'sarif'
    SANS = 'sans'


class ReportExtension(str, Enum):
    HTML = 'html'
    SARIF = 'sarif'


class ReportLocale(str, Enum):
    RU = 'ru'
    EN = 'en'


class ReportHTMLTemplate(str, Enum):
    NIST = 'nist'
    OUD4 = 'oud4'
    OWASP = 'owasp'
    OWASP_MOBILE = 'owasp_mobile'
    PCIDSS = 'pcidss'
    PLAIN = 'plain'
    SANS = 'sans'


class AuthenticationType(str, Enum):
    HTTP_BASIC = 'httpBasic'
    HTML_AUTO_FORM = 'htmlAutoForm'
    HTML_FORM_BASED = 'htmlFormBased'
    RAW_COOKIE = 'rawCookie'
    API_KEY = 'apiKey'
    BEARER = 'bearer'


class ApiKeyPlace(str, Enum):
    COOKIE = 'COOKIE'
    HEADER = 'HEADER'
    QUERY = 'QUERY'


class Authentication(TypedDict):
    pass


class HttpBasic(Authentication):
    username: str
    password: str


class HtmlAutoForm(Authentication):
    username: str
    password: str
    formUrl: str
    successString: str


class HtmlFormBased(Authentication):
    formUrl: str
    formXPath: str
    usernameField: str
    usernameValue: str
    passwordField: str
    passwordValue: str
    regexpOfSuccess: str
    submitValue: Optional[str]


class RawCookie(Authentication):
    cookies: List[str]
    successUrl: str
    regexpOfSuccess: str


class ApiKey(Authentication):
    place: ApiKeyPlace
    name: str
    value: str
    successUrl: str
    successString: Optional[str]


class Bearer(Authentication):
    token: str
    successUrl: str
    successString: Optional[str]


ReturnType = TypeVar('ReturnType')
