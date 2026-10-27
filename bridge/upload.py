"""Sends a finished report.json to a SecureBridge API (see bridge/server.py)."""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request


def upload_report(base_url: str, token: str, report_text: str, timeout: int = 15):
    """Returns (ok, message). Never raises: a failed upload must not change the verdict."""
    if not token:
        return False, "no token given (use --token or SECUREBRIDGE_TOKEN), nothing uploaded"
    body = json.dumps({"report": json.loads(report_text),
                       "commit": os.environ.get("GITHUB_SHA", ""),
                       "branch": os.environ.get("GITHUB_REF_NAME", "")}).encode()
    request = urllib.request.Request(
        base_url.rstrip("/") + "/api/v1/scans", data=body, method="POST",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            saved = json.loads(response.read())
    except urllib.error.HTTPError as error:
        return False, f"server refused the upload (HTTP {error.code}), nothing saved"
    except (urllib.error.URLError, OSError, ValueError) as error:
        return False, f"could not reach {base_url} ({error}), nothing saved"
    changes = ""
    if saved.get("new") is not None:
        changes = f"; {saved['new']} new, {saved['fixed']} fixed since the last scan"
    return True, f"saved as scan #{saved['id']}{changes}"
