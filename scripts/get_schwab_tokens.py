from __future__ import annotations

import argparse
import base64
import http.server
import json
import os
import threading
import sys
import urllib.error
import urllib.parse
import urllib.request
import webbrowser


AUTHORIZE_URL = "https://api.schwabapi.com/v1/oauth/authorize"
TOKEN_URL = "https://api.schwabapi.com/v1/oauth/token"


class _CallbackServer(http.server.HTTPServer):
    allow_reuse_address = True

    def __init__(self, server_address):
        super().__init__(server_address, _CallbackHandler)
        self.code: str | None = None
        self.error: str | None = None
        self.state: str | None = None
        self.event = threading.Event()


class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        self.server.code = params.get("code", [None])[0]
        self.server.error = params.get("error", [None])[0]
        self.server.state = params.get("state", [None])[0]

        if self.server.code:
            status = 200
            body = (
                "<html><body><h2>Authorization received.</h2>"
                "<p>You can close this window and return to your terminal.</p>"
                "</body></html>"
            )
        else:
            status = 400
            body = (
                "<html><body><h2>Authorization failed.</h2>"
                "<p>No authorization code was found in the callback URL.</p>"
                "</body></html>"
            )

        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
        self.server.event.set()

    def log_message(self, format: str, *args) -> None:
        return


def _require_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ValueError(f"Missing required environment variable: {name}")
    return value


def build_authorize_url(client_id: str, redirect_uri: str, state: str | None = None) -> str:
    query = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
    }
    if state:
        query["state"] = state
    return f"{AUTHORIZE_URL}?{urllib.parse.urlencode(query)}"


def exchange_code(client_id: str, client_secret: str, redirect_uri: str, code: str) -> dict:
    creds = f"{client_id}:{client_secret}".encode("ascii")
    basic = base64.b64encode(creds).decode("ascii")

    body = urllib.parse.urlencode(
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
        }
    ).encode("ascii")

    request = urllib.request.Request(
        TOKEN_URL,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Basic {basic}",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
            payload = response.read().decode("utf-8")
            return json.loads(payload)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Token exchange failed ({exc.code}): {detail}") from exc


def capture_code_via_callback(redirect_uri: str, timeout_seconds: int) -> tuple[str, str | None]:
    parsed = urllib.parse.urlparse(redirect_uri)
    if parsed.scheme != "http":
        raise RuntimeError(
            "Auto-callback requires SCHWAB_REDIRECT_URI to use http://localhost or http://127.0.0.1"
        )

    host = parsed.hostname
    if host not in {"localhost", "127.0.0.1"}:
        raise RuntimeError(
            "Auto-callback requires SCHWAB_REDIRECT_URI host to be localhost or 127.0.0.1"
        )

    port = parsed.port or 80
    server = _CallbackServer((host, port))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        ok = server.event.wait(timeout_seconds)
        if not ok:
            raise RuntimeError(
                f"Timed out waiting for OAuth callback after {timeout_seconds} seconds."
            )
        if not server.code:
            if server.error:
                raise RuntimeError(
                    f"OAuth callback returned error={server.error}."
                )
            raise RuntimeError("OAuth callback did not include a code.")
        return server.code, server.state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Print Schwab authorize URL, and optionally exchange an auth code for tokens. "
            "Uses SCHWAB_CLIENT_ID, SCHWAB_CLIENT_SECRET and SCHWAB_REDIRECT_URI from env."
        )
    )
    parser.add_argument(
        "--code",
        help="Authorization code from redirect URL. If omitted, only prints authorize URL.",
    )
    parser.add_argument(
        "--callback-url",
        help=(
            "Full redirected callback URL (for HTTPS callbacks). "
            "The script extracts `code` from this URL."
        ),
    )
    parser.add_argument(
        "--state",
        help="Optional OAuth state value to include in the authorize URL.",
    )
    parser.add_argument(
        "--auto",
        action="store_true",
        help=(
            "Start local callback listener and wait for OAuth code automatically. "
            "Requires SCHWAB_REDIRECT_URI with localhost/127.0.0.1."
        ),
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="Seconds to wait for callback in --auto mode (default: 300).",
    )
    parser.add_argument(
        "--open-browser",
        action="store_true",
        help="Open the authorize URL in your default browser (useful with --auto).",
    )
    args = parser.parse_args()

    try:
        client_id = _require_env("SCHWAB_CLIENT_ID")
        redirect_uri = _require_env("SCHWAB_REDIRECT_URI")
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    auth_url = build_authorize_url(client_id, redirect_uri, state=args.state)
    print("Open this URL in your browser and approve access:\n")
    print(auth_url)

    if args.open_browser:
        opened = webbrowser.open(auth_url, new=1)
        print("\nOpened browser:" if opened else "\nCould not open browser automatically.")

    code = args.code
    if args.callback_url and not code:
        parsed_callback = urllib.parse.urlparse(args.callback_url)
        callback_params = urllib.parse.parse_qs(parsed_callback.query)
        code = callback_params.get("code", [None])[0]
        callback_error = callback_params.get("error", [None])[0]
        if callback_error:
            print(f"OAuth callback returned error={callback_error}.", file=sys.stderr)
            return 1
        if not code:
            print(
                "Could not find `code` in --callback-url query string.",
                file=sys.stderr,
            )
            return 1

    if args.auto and not code:
        print(
            "\nWaiting for OAuth callback on your redirect URI. "
            f"Timeout: {args.timeout}s"
        )
        try:
            code, returned_state = capture_code_via_callback(redirect_uri, args.timeout)
        except RuntimeError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        if args.state and returned_state and returned_state != args.state:
            print(
                "State mismatch: callback state does not match the requested state.",
                file=sys.stderr,
            )
            return 1
        print("Authorization code captured from callback.")

    if not code:
        print("\nAfter redirect, copy the `code` value and run this script again with --code.")
        print("Or pass the full URL with --callback-url.")
        print("Or re-run with --auto --open-browser to capture it automatically.")
        return 0

    try:
        client_secret = _require_env("SCHWAB_CLIENT_SECRET")
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    try:
        token_data = exchange_code(client_id, client_secret, redirect_uri, code)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print("\nToken exchange succeeded.")
    refresh_token = token_data.get("refresh_token")
    if refresh_token:
        print("\nSet the refresh token in your current PowerShell session:")
        print(f"$env:SCHWAB_REFRESH_TOKEN=\"{refresh_token}\"")
        print("\nPersist for future shells:")
        print(
            "[Environment]::SetEnvironmentVariable("
            "\"SCHWAB_REFRESH_TOKEN\", "
            f"\"{refresh_token}\", "
            "\"User\")"
        )
    else:
        print("Response did not include refresh_token; full response below.")

    print("\nRaw token response:")
    print(json.dumps(token_data, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
