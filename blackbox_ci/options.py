from enum import Enum, EnumMeta
from os import getenv
from typing import Any, Dict, List, Optional, TextIO, cast

import click

from blackbox_ci.consts import (
    AUTH_API_KEY_VALUE_ENV,
    AUTH_APIKEY_VALUE_KEY,
    AUTH_DATA_OPTION,
    AUTH_PASSWORD_ENV,
    AUTH_PASSWORD_KEY,
    AUTH_PROFILE_OPTION,
    AUTH_TOKEN_ENV,
    AUTH_TOKEN_KEY,
    AUTO_CREATE_OPTION,
    NO_WAIT_OPTION,
    REPORT_DIR_OPTION,
    TARGET_FILE_OPTION,
    TARGET_URL_OPTION,
    TARGET_UUID_OPTION,
)


class EnumChoice(click.Choice):
    def __init__(
        self, enum: EnumMeta, case_sensitive: bool = False, use_value: bool = False
    ):
        self.enum = enum
        self.use_value = use_value
        choices: List[str] = [
            str(e.value) if use_value else e.name for e in cast(List[Enum], self.enum)
        ]
        super().__init__(choices=choices, case_sensitive=case_sensitive)

    def convert(
        self,
        value: Any,
        param: Optional['click.Parameter'],
        ctx: Optional['click.Context'],
    ) -> Enum:
        value = super().convert(value, param, ctx)
        if self.use_value:
            return next(e for e in cast(List[Enum], self.enum) if str(e.value) == value)
        return self.enum[value]


def check_target_source(
    *,
    target_url: Optional[str],
    target_file: Optional[TextIO],
    target_uuid: Optional[str],
    auto_create: bool,
) -> None:
    used_options = sum(
        option is not None for option in (target_url, target_file, target_uuid)
    )
    if used_options > 1:
        raise click.exceptions.UsageError(
            'Only one of '
            f'{TARGET_URL_OPTION}, {TARGET_FILE_OPTION} or {TARGET_UUID_OPTION} '
            'options allowed. '
            'Check provided options and environment variables.'
        )
    elif used_options < 1:
        raise click.exceptions.UsageError(
            'One of '
            f'{TARGET_URL_OPTION}, {TARGET_FILE_OPTION} or {TARGET_UUID_OPTION} '
            'options required.'
        )
    elif auto_create and target_uuid:
        raise click.exceptions.UsageError(
            f'{TARGET_UUID_OPTION} option cannot be used '
            f'with {AUTO_CREATE_OPTION} flag.'
        )


def check_report_output_options(
    *,
    report_dir: Optional[str],
    no_wait: bool,
    scan_uuid: Optional[str],
    results_only: bool,
) -> None:
    if results_only or scan_uuid:
        # no_wait option ignored in such cases
        # the ability to generate a report should be checked based on the scan status
        return
    if no_wait and report_dir:
        raise click.exceptions.UsageError(
            f'{REPORT_DIR_OPTION} option cannot be used with {NO_WAIT_OPTION} option. '
            'To generate a report the scan must be finished or stopped.'
        )


def check_auth_options(
    *,
    auth_profile_uuid: Optional[str],
    auth_data: Optional[TextIO],
    scan_uuid: Optional[str],
    results_only: bool,
) -> None:
    if results_only or scan_uuid:
        # auth settings options ignored in such cases
        return
    if auth_data is not None and auth_profile_uuid is not None:
        raise click.exceptions.UsageError(
            'Only one of '
            f'{AUTH_PROFILE_OPTION} or {AUTH_DATA_OPTION} '
            'options allowed. '
            'Check provided options and environment variables.'
        )


def update_auth_data_on_env(auth_data: Dict[str, str]) -> None:
    password = auth_data.get(AUTH_PASSWORD_KEY, getenv(AUTH_PASSWORD_ENV))
    if password:
        auth_data[AUTH_PASSWORD_KEY] = password
    token = auth_data.get(AUTH_TOKEN_KEY, getenv(AUTH_TOKEN_ENV))
    if token:
        auth_data[AUTH_TOKEN_KEY] = token
    api_key_value = auth_data.get(AUTH_APIKEY_VALUE_KEY, getenv(AUTH_API_KEY_VALUE_ENV))
    if api_key_value:
        auth_data[AUTH_APIKEY_VALUE_KEY] = api_key_value
