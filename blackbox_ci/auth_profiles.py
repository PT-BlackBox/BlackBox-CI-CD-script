from collections.abc import Callable
from typing import Any
from uuid import UUID

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
    AUTH_TEST_STRING_KEY,
    AUTH_TOKEN_KEY,
    AUTH_TYPE_KEY,
    AUTH_USERNAME_FIELD_KEY,
    AUTH_USERNAME_KEY,
    AuthenticationType,
)
from blackbox_ci.errors import BlackBoxError
from blackbox_ci.generated.models.api_key_place import ApiKeyPlace
from blackbox_ci.generated.models.api_key_schema import APIKeySchema
from blackbox_ci.generated.models.auth_profile_create_schema import AuthProfileCreateSchema
from blackbox_ci.generated.models.authentication_type import AuthenticationType as GeneratedAuthenticationType
from blackbox_ci.generated.models.bearer_schema import BearerSchema
from blackbox_ci.generated.models.html_auto_form_schema import HTMLAutoFormSchema
from blackbox_ci.generated.models.html_form_based_schema import HTMLFormBasedSchema
from blackbox_ci.generated.models.http_basic_schema import HTTPBasicSchema
from blackbox_ci.generated.models.raw_cookie_schema import RawCookieSchema

AuthSchema = HTTPBasicSchema | HTMLAutoFormSchema | HTMLFormBasedSchema | RawCookieSchema | APIKeySchema | BearerSchema

_AUTH_FIELD_KWARGS: dict[AuthenticationType, str] = {
    AuthenticationType.HTTP_BASIC: 'http_basic',
    AuthenticationType.HTML_AUTO_FORM: 'html_auto_form',
    AuthenticationType.HTML_FORM_BASED: 'html_form_based',
    AuthenticationType.RAW_COOKIE: 'raw_cookie',
    AuthenticationType.API_KEY: 'api_key',
    AuthenticationType.BEARER: 'bearer',
}


def build_auth_profile_body(
    *,
    group_uuid: str,
    group_name: str,
    auth_data: dict[str, str],
) -> AuthProfileCreateSchema:
    raw = auth_data.copy()
    auth_type = _pop_auth_type(raw_auth_data=raw)
    auth_schema = _convert_auth_data(raw_auth_data=raw, auth_type=auth_type)
    if raw:
        verbose = ', '.join(raw.keys())
        raise BlackBoxError(f'following fields unsupported for this auth type: {verbose}')

    body_kwargs: dict[str, Any] = {_AUTH_FIELD_KWARGS[auth_type]: auth_schema}
    return AuthProfileCreateSchema(
        group_uuid=UUID(group_uuid),
        name=group_name,
        type_=GeneratedAuthenticationType[auth_type.name],
        **body_kwargs,
    )


def _pop_auth_type(*, raw_auth_data: dict[str, str]) -> AuthenticationType:
    auth_type = raw_auth_data.pop(AUTH_TYPE_KEY, None)
    if not auth_type:
        raise BlackBoxError('authentication type should be provided')
    if auth_type not in list(AuthenticationType):
        raise BlackBoxError('unknown authentication type')
    return AuthenticationType(auth_type)


def _convert_auth_data(*, raw_auth_data: dict[str, str], auth_type: AuthenticationType) -> AuthSchema:
    converters: dict[AuthenticationType, Callable[..., AuthSchema]] = {
        AuthenticationType.HTTP_BASIC: _convert_http_basic,
        AuthenticationType.HTML_AUTO_FORM: _convert_html_auto_form,
        AuthenticationType.HTML_FORM_BASED: _convert_html_form_based,
        AuthenticationType.RAW_COOKIE: _convert_raw_cookie,
        AuthenticationType.API_KEY: _convert_api_key,
        AuthenticationType.BEARER: _convert_bearer,
    }
    return converters[auth_type](raw_auth_data=raw_auth_data)


def _convert_http_basic(*, raw_auth_data: dict[str, str]) -> HTTPBasicSchema:
    username = raw_auth_data.pop(AUTH_USERNAME_KEY, '')
    password = raw_auth_data.pop(AUTH_PASSWORD_KEY, '')
    test_string = raw_auth_data.pop(AUTH_TEST_STRING_KEY, None)
    if not username or not password:
        raise BlackBoxError('username and password should be provided')
    return HTTPBasicSchema(username=username, password=password, test_string=test_string)


def _convert_html_auto_form(*, raw_auth_data: dict[str, str]) -> HTMLAutoFormSchema:
    username = raw_auth_data.pop(AUTH_USERNAME_KEY, '')
    password = raw_auth_data.pop(AUTH_PASSWORD_KEY, '')
    form_url = raw_auth_data.pop(AUTH_FORM_URL_KEY, '')
    success_string = raw_auth_data.pop(AUTH_SUCCESS_STRING_KEY, '')
    success_url = raw_auth_data.pop(AUTH_SUCCESS_URL_KEY, None)
    if not all(
        (
            username,
            password,
            form_url,
            success_string,
        ),
    ):
        raise BlackBoxError('username, password, form url and success string should be provided')
    return HTMLAutoFormSchema(
        username=username,
        password=password,
        form_url=form_url,
        success_string=success_string,
        success_url=success_url,
    )


def _convert_html_form_based(*, raw_auth_data: dict[str, str]) -> HTMLFormBasedSchema:
    form_url = raw_auth_data.pop(AUTH_FORM_URL_KEY, '')
    form_xpath = raw_auth_data.pop(AUTH_FORM_X_PATH_KEY, '')
    username_field = raw_auth_data.pop(AUTH_USERNAME_FIELD_KEY, '')
    username_value = raw_auth_data.pop(AUTH_USERNAME_KEY, '')
    password_field = raw_auth_data.pop(AUTH_PASSWORD_FIELD_KEY, '')
    password_value = raw_auth_data.pop(AUTH_PASSWORD_KEY, '')
    regexp_of_success = raw_auth_data.pop(AUTH_REGEXP_OF_SUCCESS_KEY, '')
    submit_value = raw_auth_data.pop(AUTH_SUBMIT_VALUE_KEY, None)
    success_url = raw_auth_data.pop(AUTH_SUCCESS_URL_KEY, None)
    if not all(
        (
            form_url,
            form_xpath,
            username_field,
            username_value,
            password_field,
            password_value,
            regexp_of_success,
        ),
    ):
        raise BlackBoxError(
            'form url, form xpath, username field, username value, password field, '
            'password value and regexp of success string should be provided',
        )
    return HTMLFormBasedSchema(
        form_url=form_url,
        form_x_path=form_xpath,
        username_field=username_field,
        username_value=username_value,
        password_field=password_field,
        password_value=password_value,
        regexp_of_success=regexp_of_success,
        submit_value=submit_value,
        success_url=success_url,
    )


def _convert_raw_cookie(*, raw_auth_data: dict[str, str]) -> RawCookieSchema:
    cookies = raw_auth_data.pop(AUTH_COOKIES_KEY, '')
    success_url = raw_auth_data.pop(AUTH_SUCCESS_URL_KEY, '')
    regexp_of_success = raw_auth_data.pop(AUTH_REGEXP_OF_SUCCESS_KEY, '')
    if not all(
        (
            cookies,
            success_url,
            regexp_of_success,
        ),
    ):
        raise BlackBoxError('cookies, success url and regexp of success should be provided')
    return RawCookieSchema(
        cookies=cookies.rstrip(';').split(';'),
        success_url=success_url,
        regexp_of_success=regexp_of_success,
    )


def _convert_api_key(*, raw_auth_data: dict[str, str]) -> APIKeySchema:
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
        ),
    ):
        raise BlackBoxError('place, name, value and success url should be provided')
    if place not in list(ApiKeyPlace):
        verbose = ', '.join(ApiKeyPlace)
        raise BlackBoxError(f'place can be one of: {verbose}')
    return APIKeySchema(
        place=ApiKeyPlace(place),
        name=name,
        value=value,
        success_url=success_url,
        success_string=success_string,
    )


def _convert_bearer(*, raw_auth_data: dict[str, str]) -> BearerSchema:
    token = raw_auth_data.pop(AUTH_TOKEN_KEY, '')
    success_url = raw_auth_data.pop(AUTH_SUCCESS_URL_KEY, '')
    success_string = raw_auth_data.pop(AUTH_SUCCESS_STRING_KEY, None)
    if not all(
        (
            token,
            success_url,
        ),
    ):
        raise BlackBoxError('token and success url should be provided')
    return BearerSchema(
        token=token,
        success_url=success_url,
        success_string=success_string,
    )
