import json
import os

import radiusd
import requests
import yaml

import otp_check

MODCONF_DIR = os.path.dirname(os.path.abspath(__file__))
ASGARDEO_CONFIG_PATH = os.path.join(MODCONF_DIR, "asgardeo_config.json")
GROUP_MAP_PATH = os.path.join(MODCONF_DIR, "vpn_group_map.yaml")

OTP_LENGTH = 6

_config = {}
_group_map = {}


class AsgardeoUnreachable(Exception):
    """Raised for network failures or unexpected Asgardeo server errors."""


def _load_json(path):
    with open(path) as f:
        return json.load(f)


def _load_config():
    global _config, _group_map

    _config = _load_json(ASGARDEO_CONFIG_PATH)

    with open(GROUP_MAP_PATH) as f:
        _group_map = yaml.safe_load(f) or {}


def instantiate(p=None):
    try:
        _load_config()
    except Exception as exc:  # noqa: BLE001
        radiusd.radlog(
            radiusd.L_ERR,
            "radius_policy: failed to load config: %s" % exc,
        )
        return radiusd.RLM_MODULE_FAIL

    radiusd.radlog(
        radiusd.L_INFO,
        "radius_policy: loaded %d group mapping(s)"
        % len(_group_map),
    )

    return radiusd.RLM_MODULE_OK


def _attr(request_tuple, name):
    """Pull a single attribute value from the request tuple."""
    for key, value in request_tuple:
        if key == name:
            return value.strip('"') if isinstance(value, str) else value
    return None


def split_password(raw_password, otp_length=OTP_LENGTH):
    """Split '<password><6-digit-otp>' into (base_password, otp_code)."""

    if not raw_password or len(raw_password) <= otp_length:
        return None, None

    otp_code = raw_password[-otp_length:]
    base_password = raw_password[:-otp_length]

    if not otp_code.isdigit():
        return None, None

    return base_password, otp_code


def check_password_ropc(username, password):
    """Validate username/password against Asgardeo ROPC."""

    timeout = _config.get("http_timeout_seconds", 3)

    data = {
        "grant_type": "password",
        "username": username,
        "password": password,
        "client_id": _config["ropc_client_id"],
        "client_secret": _config["ropc_client_secret"],
        "scope": _config.get("ropc_scope", "openid"),
    }

    try:
        resp = requests.post(
            _config["token_endpoint"],
            data=data,
            timeout=timeout,
        )

    except (
        requests.exceptions.ConnectionError,
        requests.exceptions.Timeout,
    ) as exc:
        raise AsgardeoUnreachable(
            "ROPC call failed: %s" % exc
        ) from exc

    if resp.status_code == 200:
        return resp.json()

    if resp.status_code in (400, 401):
        return None

    raise AsgardeoUnreachable(
        "ROPC call returned unexpected status %d"
        % resp.status_code
    )


def fetch_groups_via_userinfo(access_token):
    """Fetch the authenticated user's group membership."""

    timeout = _config.get("http_timeout_seconds", 3)

    headers = {
        "Authorization": "Bearer %s" % access_token
    }

    try:
        resp = requests.get(
            _config["userinfo_endpoint"],
            headers=headers,
            timeout=timeout,
        )

    except (
        requests.exceptions.ConnectionError,
        requests.exceptions.Timeout,
    ) as exc:
        raise AsgardeoUnreachable(
            "userinfo call failed: %s" % exc
        ) from exc

    if resp.status_code != 200:
        return []

    claim_name = _config.get("groups_claim", "groups")

    groups = resp.json().get(claim_name, [])

    if isinstance(groups, str):
        groups = [groups]

    return groups


def map_groups_to_fortinet(groups):
    """Map the first matching Asgardeo group to Fortinet-Group-Name."""

    for group in groups:
        if group in _group_map:
            return _group_map[group]

    return None


def _reject(reason):
    radiusd.radlog(
        radiusd.L_AUTH,
        "radius_policy: reject - %s" % reason,
    )

    return (
        radiusd.RLM_MODULE_UPDATED,
        (),
        (("Auth-Type", ":=", "Reject"),),
    )


def _accept(fortinet_group):
    reply = (
        ("Fortinet-Group-Name", ":=", fortinet_group),
    )

    config = (
        ("Auth-Type", ":=", "Accept"),
    )

    return (
        radiusd.RLM_MODULE_UPDATED,
        reply,
        config,
    )


def authorize(p):
    username = _attr(p, "User-Name")
    raw_password = _attr(p, "User-Password")

    if not username or not raw_password:
        return _reject(
            "missing User-Name or User-Password in inner request"
        )

    base_password, otp_code = split_password(raw_password)

    if base_password is None:
        return _reject(
            "malformed password for '%s' "
            "(expected <password><%d-digit-otp>)"
            % (username, OTP_LENGTH)
        )

    # ---------------------------------------------------------
    # 1. Authenticate username/password against Asgardeo
    # ---------------------------------------------------------

    try:
        token_response = check_password_ropc(
            username,
            base_password,
        )

    except AsgardeoUnreachable as exc:
        radiusd.radlog(
            radiusd.L_ERR,
            "radius_policy: Asgardeo unreachable for '%s': %s"
            % (username, exc),
        )

        return _reject(
            "Asgardeo authentication service unavailable"
        )

    if token_response is None:
        return _reject(
            "invalid Asgardeo credentials for '%s'"
            % username
        )

    # ---------------------------------------------------------
    # 2. Fetch user's Asgardeo groups
    # ---------------------------------------------------------

    try:
        groups = fetch_groups_via_userinfo(
            token_response["access_token"]
        )

    except AsgardeoUnreachable as exc:
        radiusd.radlog(
            radiusd.L_ERR,
            "radius_policy: unable to fetch groups for '%s': %s"
            % (username, exc),
        )

        return _reject(
            "unable to retrieve Asgardeo user groups"
        )

    # ---------------------------------------------------------
    # 3. Validate OTP
    # ---------------------------------------------------------

    if not otp_check.validate_otp(username, otp_code):
        return _reject(
            "invalid OTP for '%s'" % username
        )

    # ---------------------------------------------------------
    # 4. Map Asgardeo group to Fortinet group
    # ---------------------------------------------------------

    fortinet_group = map_groups_to_fortinet(groups)

    if not fortinet_group:
        return _reject(
            "'%s' authenticated but has no mapped VPN group "
            "(groups seen: %s)"
            % (username, groups)
        )

    # ---------------------------------------------------------
    # 5. Accept
    # ---------------------------------------------------------

    radiusd.radlog(
        radiusd.L_AUTH,
        "radius_policy: accept - '%s' -> "
        "Fortinet-Group-Name=%s"
        % (username, fortinet_group),
    )

    return _accept(fortinet_group)
