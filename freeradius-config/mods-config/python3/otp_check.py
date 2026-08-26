import base64
import hashlib
import hmac
import json
import os
import re
import struct
import time
from contextlib import contextmanager

import radiusd

MODCONF_DIR = os.path.dirname(os.path.abspath(__file__))
SECRETS_DIR = os.path.join(MODCONF_DIR, "otp_secrets")
STATE_DIR = os.path.join(MODCONF_DIR, "otp_state")

STEP_SECONDS = 30
DIGITS = 6
WINDOW_STEPS = 1  # accept current step +/- 1 (i.e. +/- 30s of drift)

FAILURE_WINDOW_SECONDS = 600  # 10 minutes
FAILURE_THRESHOLD = 5

_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9_.-]")


def _safe_filename(username):
    """Defends the secrets/state directories against a crafted User-Name
    containing path-traversal characters (e.g. '../../etc/passwd')."""
    cleaned = _SAFE_NAME_RE.sub("_", username)
    return cleaned or "_invalid_"


def _secret_path(username):
    return os.path.join(SECRETS_DIR, _safe_filename(username) + ".secret")


def _state_path(username):
    return os.path.join(STATE_DIR, _safe_filename(username) + ".json")


def _lock_path(username):
    return os.path.join(STATE_DIR, _safe_filename(username) + ".lock")


@contextmanager
def _locked(username):
    import fcntl

    lock_file = open(_lock_path(username), "a+")
    try:
        fcntl.flock(lock_file, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(lock_file, fcntl.LOCK_UN)
        lock_file.close()


def _load_secret(username):
    path = _secret_path(username)

    if not os.path.isfile(path):
        return None

    with open(path) as f:
        raw = f.read().strip()

    padding = "=" * ((8 - len(raw) % 8) % 8)

    return base64.b32decode(raw.upper() + padding)


def _load_state(username):
    path = _state_path(username)

    if not os.path.isfile(path):
        return {
            "last_used_counter": -1,
            "recent_failures": []
        }

    try:
        with open(path) as f:
            return json.load(f)
    except (ValueError, OSError):
        return {
            "last_used_counter": -1,
            "recent_failures": []
        }


def _save_state(username, state):
    path = _state_path(username)
    tmp_path = path + ".tmp"

    with open(tmp_path, "w") as f:
        json.dump(state, f)

    os.replace(tmp_path, path)


def _hotp(secret_bytes, counter, digits=DIGITS):
    msg = struct.pack(">Q", counter)

    digest = hmac.new(
        secret_bytes,
        msg,
        hashlib.sha1
    ).digest()

    offset = digest[-1] & 0x0F

    code_int = (
        struct.unpack(">I", digest[offset:offset + 4])[0]
        & 0x7FFFFFFF
    ) % (10 ** digits)

    return str(code_int).zfill(digits)


def _prune_failures(failures, now):
    return [
        t
        for t in failures
        if now - t < FAILURE_WINDOW_SECONDS
    ]


def _find_matching_counter(
    secret_bytes,
    otp_code,
    now,
    last_used_counter
):
    current_counter = int(now // STEP_SECONDS)

    for delta in range(
        -WINDOW_STEPS,
        WINDOW_STEPS + 1
    ):
        counter = current_counter + delta

        if counter <= last_used_counter:
            continue

        candidate = _hotp(
            secret_bytes,
            counter
        )

        if hmac.compare_digest(
            candidate,
            otp_code
        ):
            return counter

    return None


def validate_otp(username, otp_code, now=None):
    if now is None:
        now = time.time()

    if (
        not otp_code
        or not otp_code.isdigit()
        or len(otp_code) != DIGITS
    ):
        radiusd.radlog(
            radiusd.L_AUTH,
            "otp_check: malformed OTP for '%s'" % username
        )
        return False

    secret_bytes = _load_secret(username)

    if secret_bytes is None:
        radiusd.radlog(
            radiusd.L_AUTH,
            "otp_check: no TOTP secret enrolled for '%s'"
            % username
        )
        return False

    with _locked(username):
        state = _load_state(username)

        state["recent_failures"] = _prune_failures(
            state.get("recent_failures", []),
            now
        )

        if len(state["recent_failures"]) >= FAILURE_THRESHOLD:
            radiusd.radlog(
                radiusd.L_AUTH,
                "otp_check: '%s' is rate-limited after %d "
                "recent OTP failures"
                % (
                    username,
                    len(state["recent_failures"])
                )
            )

            _save_state(username, state)

            return False

        matched_counter = _find_matching_counter(
            secret_bytes,
            otp_code,
            now,
            state.get("last_used_counter", -1)
        )

        if matched_counter is None:
            state["recent_failures"].append(now)

            _save_state(username, state)

            radiusd.radlog(
                radiusd.L_AUTH,
                "otp_check: invalid OTP for '%s'"
                % username
            )

            return False

        state["last_used_counter"] = matched_counter
        state["recent_failures"] = []

        _save_state(username, state)

        return True
