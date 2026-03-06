#! /usr/bin/env python3
#
# Derived from PostgreSQL's src/test/modules/oauth_validator/t/oauth_server.py
# PostgreSQL source commit: aa7c86852343dd18f5834f70e4caa50ae49326c9
# Original: Copyright (c) 1996-2026, PostgreSQL Global Development Group
# Licensed under the PostgreSQL License (https://www.postgresql.org/about/licence/)
#
# Modifications for standalone use and JWT token generation:
# - _access_token returns a crafted unsigned JWT with configurable claims
# - TLS cert/key paths from env vars MOCK_OAUTH_CERT / MOCK_OAUTH_KEY
# - GET /healthz -> 200 OK for container readiness
# - Removed stdout-close / daemonize lifecycle; runs as normal server
# - Preserved /param/ mechanism for test-controlled responses
#

import base64
import functools
import http.server
import json
import os
import ssl
import sys
import time
import urllib.parse
from collections import defaultdict
from typing import Dict

ssl_cert = os.getenv("MOCK_OAUTH_CERT") or (os.getenv("cert_dir", "") + "/server-localhost-alt-names.crt")
ssl_key  = os.getenv("MOCK_OAUTH_KEY")  or (os.getenv("cert_dir", "") + "/server-localhost-alt-names.key")


def _b64url(data: bytes) -> str:
    """Base64url-encode bytes (no padding)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _make_jwt(claims: dict, port: int) -> str:
    """
    Build an unsigned JWT (alg=none) with the given claims.
    Adds iss, iat, exp defaults if not present.
    """
    claims.setdefault("iss", f"https://127.0.0.1:{port}")
    claims.setdefault("iat", int(time.time()))
    claims.setdefault("exp", int(time.time()) + 3600)

    header  = _b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps(claims).encode())
    # Unsigned JWT: header.payload. (empty signature)
    return f"{header}.{payload}."


class OAuthHandler(http.server.BaseHTTPRequestHandler):
    """
    Mock OAuth authorization server implementing:
    - GET  /.well-known/openid-configuration  — OIDC discovery
    - POST /authorize                          — Device authorization
    - POST /token                              — Token exchange
    - GET  /healthz                            — Readiness probe
    """

    JsonObject = Dict[str, object]

    def log_message(self, format, *args):  # noqa: A002
        print(f"[mock-oauth] {self.address_string()} - {format % args}", file=sys.stderr)

    def _check_issuer(self):
        self._alt_issuer     = (
            self.path.startswith("/alternate/")
            or self.path == "/.well-known/oauth-authorization-server/alternate"
        )
        self._parameterized  = self.path.startswith("/param/")

        if self._alt_issuer:
            if self.path.startswith("/.well-known/"):
                self.path = self.path[: -len("/alternate")]
            else:
                self.path = self.path[len("/alternate"):]
        elif self._parameterized:
            self.path = self.path[len("/param"):]

    def _check_authn(self):
        secret = self._get_param("expected_secret", None)
        if secret is None:
            return

        assert "Authorization" in self.headers
        method, creds = self.headers["Authorization"].split()

        if method != "Basic":
            raise RuntimeError(f"client used {method} auth; expected Basic")

        username = urllib.parse.quote_plus(self.client_id, safe="~")
        password = urllib.parse.quote_plus(secret, safe="~")
        expected_creds = f"{username}:{password}"

        if creds.encode() != base64.b64encode(expected_creds.encode()):
            raise RuntimeError(
                f"client sent '{creds}'; expected b64encode('{expected_creds}')"
            )

    def do_GET(self):
        self._response_code = 200
        self._check_issuer()

        if self.path == "/healthz":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
            return

        config_path = "/.well-known/openid-configuration"
        if self._alt_issuer:
            config_path = "/.well-known/oauth-authorization-server"

        if self.path == config_path:
            resp = self.config()
        else:
            self.send_error(404, "Not Found")
            return

        self._send_json(resp)

    def _parse_params(self) -> Dict[str, str]:
        size = int(self.headers["Content-Length"])
        form = self.rfile.read(size)
        assert self.headers["Content-Type"] == "application/x-www-form-urlencoded"
        return urllib.parse.parse_qs(
            form.decode("utf-8"),
            strict_parsing=True,
            keep_blank_values=True,
            encoding="utf-8",
            errors="strict",
        )

    @property
    def client_id(self) -> str:
        if "client_id" in self._params:
            return self._params["client_id"][0]

        if "Authorization" not in self.headers:
            raise RuntimeError("client did not send any client_id")

        _, creds = self.headers["Authorization"].split()
        decoded = base64.b64decode(creds).decode("utf-8")
        username, _ = decoded.split(":", 1)
        return urllib.parse.unquote_plus(username)

    def do_POST(self):
        self._response_code = 200
        self._check_issuer()

        self._params = self._parse_params()
        if self._parameterized:
            js = base64.b64decode(self.client_id)
            self._test_params = json.loads(js)

        self._check_authn()

        if self.path == "/authorize":
            resp = self.authorization()
        elif self.path == "/token":
            resp = self.token()
        else:
            self.send_error(404)
            return

        self._send_json(resp)

    def _should_modify(self) -> bool:
        if not hasattr(self, "_test_params"):
            return False
        stage = self._test_params.get("stage")
        return (
            stage == "all"
            or (stage == "discovery" and self.path == "/.well-known/openid-configuration")
            or (stage == "device" and self.path == "/authorize")
            or (stage == "token" and self.path == "/token")
        )

    def _get_param(self, name, default):
        if self._should_modify() and name in self._test_params:
            return self._test_params[name]
        return default

    @property
    def _content_type(self) -> str:
        return self._get_param("content_type", "application/json")

    @property
    def _interval(self) -> int:
        return self._get_param("interval", 0)

    @property
    def _retry_code(self) -> str:
        return self._get_param("retry_code", "authorization_pending")

    @property
    def _uri_spelling(self) -> str:
        return self._get_param("uri_spelling", "verification_uri")

    @property
    def _response_padding(self):
        ret = dict()
        if self._get_param("huge_response", False):
            ret["_pad_"] = "x" * 1024 * 1024
        depth = self._get_param("nested_array", 0)
        if depth:
            ret["_arr_"] = functools.reduce(lambda x, _: [x], range(depth))
        depth = self._get_param("nested_object", 0)
        if depth:
            ret["_obj_"] = functools.reduce(lambda x, _: {"": x}, range(depth))
        return ret

    @property
    def _access_token(self):
        """
        Returns a crafted unsigned JWT. Test params can override individual
        claims via the 'claims' key in the test_params dict, or override the
        whole token with the 'token' key.
        """
        # Allow complete override
        raw = self._get_param("token", None)
        if raw is not None:
            return raw

        port = self.server.socket.getsockname()[1]

        # Default Entra-like claims
        claims = {
            "sub": "testuser-oid-12345",
            "preferred_username": "testuser@example.com",
            "roles": ["db_user"],
        }
        if self._alt_issuer:
            claims["preferred_username"] = "altuser@example.com"
            claims["roles"] = ["db_user"]

        # Allow test to override individual claims.
        # Setting a claim value to null removes it from the token.
        claim_overrides = self._get_param("claims", {})
        if claim_overrides:
            claims.update(claim_overrides)
            claims = {k: v for k, v in claims.items() if v is not None}

        return _make_jwt(claims, port)

    def _log_response(self, js: JsonObject) -> None:
        if "_pad_" in js:
            pad = js["_pad_"]
            js = dict(js)
            js["_pad_"] = pad[:64] + f"[...truncated from {len(pad)} bytes]"

        resp = json.dumps(js).encode("ascii")
        # Only log non-JWT responses (tokens are long)
        if len(resp) < 1024:
            self.log_message("sending JSON response: %s", resp)
        else:
            self.log_message("sending JSON response: <large response, %d bytes>", len(resp))

    def _send_json(self, js: JsonObject) -> None:
        resp = json.dumps(js).encode("ascii")
        self._log_response(js)
        self.send_response(self._response_code)
        self.send_header("Content-Type", self._content_type)
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

    def config(self) -> JsonObject:
        port = self.server.socket.getsockname()[1]
        # Use the Host header so the issuer matches whatever oauth_issuer psql was given.
        # Fall back to 127.0.0.1 if no Host header.
        host = self.headers.get("Host", f"127.0.0.1:{port}")
        issuer = f"https://{host}"
        if self._alt_issuer:
            issuer += "/alternate"
        elif self._parameterized:
            issuer += "/param"

        return {
            "issuer": issuer,
            "token_endpoint": issuer + "/token",
            "device_authorization_endpoint": issuer + "/authorize",
            "response_types_supported": ["token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "grant_types_supported": [
                "authorization_code",
                "urn:ietf:params:oauth:grant-type:device_code",
            ],
        }

    @property
    def _token_state(self):
        return self.server.token_state[self.client_id]

    def _remove_token_state(self):
        if self.client_id in self.server.token_state:
            del self.server.token_state[self.client_id]

    def authorization(self) -> JsonObject:
        uri = "https://example.com/"
        if self._alt_issuer:
            uri = "https://example.org/"

        resp = {
            "device_code": "postgres",
            "user_code": "postgresuser",
            self._uri_spelling: uri,
            "expires_in": 5,
            **self._response_padding,
        }

        interval = self._interval
        if interval is not None:
            resp["interval"] = interval
            self._token_state.min_delay = interval
        else:
            self._token_state.min_delay = 5

        if "scope" in self._params:
            assert self._params["scope"][0], "empty scopes should be omitted"

        return resp

    def token(self) -> JsonObject:
        err = self._get_param("error_code", None)
        if err:
            self._response_code = self._get_param("error_status", 400)
            resp = {"error": err}
            desc = self._get_param("error_desc", "")
            if desc:
                resp["error_description"] = desc
            return resp

        if self._should_modify() and "retries" in self._test_params:
            retries = self._test_params["retries"]
            now = time.monotonic()
            if self._token_state.last_try is not None:
                delay = now - self._token_state.last_try
                assert (
                    delay > self._token_state.min_delay
                ), f"client waited only {delay} seconds between token requests (expected {self._token_state.min_delay})"

            self._token_state.last_try = now

            if self._token_state.retries < retries:
                self._token_state.retries += 1
                self._response_code = 400
                return {"error": self._retry_code}

        self._remove_token_state()

        return {
            "access_token": self._access_token,
            "token_type": "bearer",
            **self._response_padding,
        }


def main():
    port_arg = int(sys.argv[1]) if len(sys.argv) > 1 else 0

    s = http.server.HTTPServer(("0.0.0.0", port_arg), OAuthHandler)

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(ssl_cert, ssl_key)
    s.socket = ssl_context.wrap_socket(s.socket, server_side=True)

    class _TokenState:
        retries = 0
        min_delay = None
        last_try = None

    s.token_state = defaultdict(_TokenState)

    port = s.socket.getsockname()[1]
    print(f"Mock OAuth server listening on port {port}", file=sys.stderr)
    print(port)  # stdout: port number for callers
    sys.stdout.flush()

    try:
        s.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
