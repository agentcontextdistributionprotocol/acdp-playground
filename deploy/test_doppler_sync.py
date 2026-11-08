"""Offline tests for deploy/doppler-sync.sh: fail closed, and keep secrets off argv.

The script runs for real against fake ``curl`` and ``doppler`` executables (and
a ``jq`` wrapper that logs its argv, then runs the real jq). The fake curl
plays Railway's GraphQL endpoint with an in-file variable store, so the tests
can see exactly what was written. Every failure mode must exit non-zero, report
no key as new or changed, and write nothing. Sentinel token and secret values
must never appear in any process's argv or in the script's output.

Needs bash, jq, git and shasum on PATH (CI's ubuntu runner has them). Run with
``uv run pytest deploy/test_doppler_sync.py``.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
TOKEN = "SENTINEL-RAILWAY-TOKEN-7f3a"
SECRET = "SENTINEL-SECRET-VALUE-c41d"
KEYS = ["ALPHA", "BETA_SECRET"]
# target -> the Railway service name the script resolves it to
TARGETS = {"playground": "acdp-playground", "registry-a": "registry-a", "registry-b": "registry-b"}
PROJECT_IDS = {
    "project": {
        "environments": {"edges": [{"node": {"id": "env-1", "name": "production"}}]},
        "services": {
            "edges": [{"node": {"id": f"svc-{t}", "name": name}} for t, name in TARGETS.items()]
        },
    }
}

if shutil.which("jq") is None or shutil.which("shasum") is None:
    pytest.skip("jq and shasum are needed", allow_module_level=True)

FAKE_CURL = r'''#!PYTHON
"""Fake curl for backboard.railway.com/graphql/v2, driven by $FAKE_DIR files."""
import json, os, sys
d = os.environ["FAKE_DIR"]
with open(os.path.join(d, "argv.log"), "a") as f:
    f.write(json.dumps(sys.argv) + "\n")
args = sys.argv[1:]
headers, wfmt, i = [], None, 0
expected_auth = "Authorization: Bearer " + os.environ["FAKE_EXPECT_TOKEN"]
while i < len(args):
    a = args[i]
    if a == "-H":
        v = args[i + 1]
        if v.startswith("@"):
            headers += open(v[1:]).read().splitlines()
        else:
            headers.append(v)
        i += 2
    elif a in ("-w", "--max-time"):
        if a == "-w":
            wfmt = args[i + 1]
        i += 2
    else:
        i += 1
body = sys.stdin.read()
req = json.loads(body)
q = req["query"]
with open(os.path.join(d, "requests.jsonl"), "a") as f:
    f.write(json.dumps({"query": q, "headers": headers}) + "\n")
mode = os.environ.get("FAKE_MODE", "ok")
fail_on = os.environ.get("FAKE_FAIL_ON", "")
failing = mode != "ok" and fail_on in q
code, out = 200, None
if expected_auth not in headers:
    # What Railway really does with a bad or expired token.
    out = {"data": None, "errors": [{"message": "Not Authorized"}]}
elif failing and mode == "network":
    sys.stderr.write("curl: (6) Could not resolve host: backboard.railway.com\n")
    sys.exit(6)
elif failing and mode == "errors":
    out = {"data": None, "errors": [{"message": "Not Authorized"}]}
elif failing and mode == "nulldata":
    out = {"data": None}
elif failing and mode == "nodata":
    out = {}
elif failing and mode == "http500":
    code, out = 500, {"error": "internal"}
elif failing and mode == "http401":
    code, out = 401, {"errors": [{"message": "Unauthorized"}]}
elif failing and mode == "garbage":
    out = "<html>bad gateway</html>"
elif failing and mode.startswith("vars="):
    out = {"data": {"variables": json.loads(mode[len("vars="):])}}
elif "project(id" in q:
    out = {"data": json.load(open(os.path.join(d, "ids.json")))}
elif "variables(projectId" in q:
    out = {"data": {"variables": json.load(open(os.path.join(d, "railway.json")))}}
elif "variableUpsert" in q:
    i = req["variables"]["i"]
    store = json.load(open(os.path.join(d, "railway.json")))
    store[i["name"]] = i["value"]
    json.dump(store, open(os.path.join(d, "railway.json"), "w"))
    out = {"data": {"variableUpsert": True}}
elif "serviceInstanceRedeploy" in q:
    out = {"data": {"serviceInstanceRedeploy": True}}
else:
    code, out = 400, {"errors": [{"message": "unknown query"}]}
text = out if isinstance(out, str) else json.dumps(out)
sys.stdout.write(text)
if wfmt is not None:
    sys.stdout.write(wfmt.replace("\\n", "\n").replace("%{http_code}", str(code)))
'''

FAKE_DOPPLER = r"""#!PYTHON
import json, os, sys
d = os.environ["FAKE_DIR"]
with open(os.path.join(d, "argv.log"), "a") as f:
    f.write(json.dumps(sys.argv) + "\n")
if os.environ.get("FAKE_DOPPLER") == "fail":
    sys.stderr.write("Doppler Error: unable to authenticate\n")
    sys.exit(1)
if os.environ.get("FAKE_DOPPLER") == "garbage":
    sys.stdout.write("Doppler Error: not json\n")
    sys.exit(0)
if os.environ.get("FAKE_DOPPLER") == "empty":
    sys.exit(0)
sys.stdout.write(open(os.path.join(d, "doppler.json")).read())
"""

# Logs argv to $FAKE_DIR/argv.log (NUL-separated, one call per line), then execs
# the real tool. The fake curl and doppler log their own argv to the same file.
LOGGING_WRAPPER = textwrap.dedent(
    """\
    #!/usr/bin/env bash
    printf '%s\\0' "$(basename "$0")" "$@" >>"$FAKE_DIR/argv.log"
    printf '\\n' >>"$FAKE_DIR/argv.log"
    exec REAL "$@"
    """
)


def _write_exec(path: Path, text: str) -> None:
    path.write_text(text.replace("#!PYTHON", f"#!{sys.executable}"))
    path.chmod(0o755)


@pytest.fixture
def env(tmp_path: Path):
    """A committed copy of the script plus fake tools; returns a runner."""
    repo = tmp_path / "repo"
    (repo / "deploy" / "doppler-keys").mkdir(parents=True)
    shutil.copy(HERE / "doppler-sync.sh", repo / "deploy" / "doppler-sync.sh")
    for target in TARGETS:
        (repo / "deploy" / "doppler-keys" / f"{target}.txt").write_text(
            "# test allowlist\n" + "\n".join(KEYS) + "\n"
        )
    git = ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid"]
    subprocess.run([*git, "init", "-q"], check=True)
    subprocess.run([*git, "add", "."], check=True)
    subprocess.run([*git, "commit", "-qm", "init"], check=True)

    fake = tmp_path / "fake"
    bin_ = tmp_path / "bin"
    fake.mkdir()
    bin_.mkdir()
    _write_exec(bin_ / "curl", FAKE_CURL)
    _write_exec(bin_ / "doppler", FAKE_DOPPLER)
    real_jq = shutil.which("jq")
    (bin_ / "jq").write_text(LOGGING_WRAPPER.replace("REAL", real_jq))
    (bin_ / "jq").chmod(0o755)
    (fake / "ids.json").write_text(json.dumps(PROJECT_IDS))
    (fake / "doppler.json").write_text(json.dumps({"ALPHA": "a1", "BETA_SECRET": SECRET}))
    (fake / "railway.json").write_text(
        json.dumps({"ALPHA": "a1", "BETA_SECRET": SECRET, "RAILWAY_X": "r"})
    )
    home = tmp_path / "home"
    home.mkdir()

    def run(
        *args: str, target: str = "playground", **extra: str
    ) -> subprocess.CompletedProcess[str]:
        e = {
            "PATH": f"{bin_}{os.pathsep}{os.environ['PATH']}",
            "HOME": str(home),
            "FAKE_DIR": str(fake),
            "FAKE_EXPECT_TOKEN": TOKEN,
            "RAILWAY_API_TOKEN": TOKEN,
            **extra,
        }
        return subprocess.run(
            ["bash", str(repo / "deploy" / "doppler-sync.sh"), target, *args],
            env=e,
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )

    run.fake = fake  # type: ignore[attr-defined]
    return run


def _requests(fake: Path) -> list[dict]:
    p = fake / "requests.jsonl"
    return [json.loads(line) for line in p.read_text().splitlines()] if p.exists() else []


def _writes(fake: Path) -> list[str]:
    return [
        r["query"]
        for r in _requests(fake)
        if "variableUpsert" in r["query"] or "serviceInstanceRedeploy" in r["query"]
    ]


def _assert_no_leak(fake: Path, result: subprocess.CompletedProcess[str]) -> None:
    out = result.stdout + result.stderr
    assert TOKEN not in out and SECRET not in out
    argv = (fake / "argv.log").read_text() if (fake / "argv.log").exists() else ""
    assert TOKEN not in argv, "the Railway token reached a process's argv"
    assert SECRET not in argv, "a secret value reached a process's argv"


def _assert_failed_closed(fake: Path, result: subprocess.CompletedProcess[str]) -> None:
    assert result.returncode != 0, result.stderr
    assert "\tnew" not in result.stderr and "\tchanged" not in result.stderr
    assert "nothing changed" in result.stderr or "no redeploy" in result.stderr
    assert _writes(fake) == []
    _assert_no_leak(fake, result)


# ── happy paths ──────────────────────────────────────────────────────────────


def test_dry_run_in_sync_reports_unchanged_and_writes_nothing(env):
    r = env()
    assert r.returncode == 0, r.stderr
    assert "ALPHA\tunchanged" in r.stderr and "BETA_SECRET\tunchanged" in r.stderr
    assert "(match)" in r.stderr and "nothing to change" in r.stderr
    assert "left alone (not in doppler-keys/playground.txt): RAILWAY_X" in r.stderr
    assert _writes(env.fake) == []
    _assert_no_leak(env.fake, r)


def test_token_reaches_curl_on_a_descriptor_not_argv(env):
    r = env()
    assert r.returncode == 0, r.stderr
    reqs = _requests(env.fake)
    assert reqs and all(f"Authorization: Bearer {TOKEN}" in q["headers"] for q in reqs)
    curl_calls = [
        json.loads(line)
        for line in (env.fake / "argv.log").read_text().splitlines()
        if line.startswith("[") and json.loads(line)[0].endswith("curl")
    ]
    assert curl_calls, "the fake curl did not log its argv"
    _assert_no_leak(env.fake, r)


def test_apply_sets_only_changed_keys_then_redeploys(env):
    (env.fake / "doppler.json").write_text(json.dumps({"ALPHA": "a2", "BETA_SECRET": SECRET}))
    r = env("--apply")
    assert r.returncode == 0, r.stderr
    assert "ALPHA\tchanged" in r.stderr and "BETA_SECRET\tunchanged" in r.stderr
    assert "hash after apply" in r.stderr and "redeploy triggered" in r.stderr
    writes = _writes(env.fake)
    assert len(writes) == 2 and "variableUpsert" in writes[0]
    assert json.loads((env.fake / "railway.json").read_text())["ALPHA"] == "a2"
    _assert_no_leak(env.fake, r)


def test_apply_with_nothing_to_change_does_not_redeploy(env):
    r = env("--apply")
    assert r.returncode == 0, r.stderr
    assert "nothing to change; no redeploy" in r.stderr
    assert _writes(env.fake) == []


# ── fail closed ──────────────────────────────────────────────────────────────

FAILURES = ["errors", "nulldata", "nodata", "http500", "http401", "network", "garbage"]


@pytest.mark.parametrize("mode", FAILURES)
@pytest.mark.parametrize("fail_on", ["project(id", "variables(projectId"])
@pytest.mark.parametrize("args", [(), ("--apply",)], ids=["dry-run", "apply"])
def test_railway_read_failure_fails_closed(env, mode, fail_on, args):
    # Make Doppler differ, so a script that misread Railway would have work to do.
    (env.fake / "doppler.json").write_text(json.dumps({"ALPHA": "a2", "BETA_SECRET": SECRET}))
    r = env(*args, FAKE_MODE=mode, FAKE_FAIL_ON=fail_on)
    _assert_failed_closed(env.fake, r)


def test_railway_200_with_null_data_and_errors_names_the_error(env):
    """The bad-token case: HTTP 200, data: null, errors: [...]."""
    r = env(FAKE_MODE="errors", FAKE_FAIL_ON="")
    _assert_failed_closed(env.fake, r)
    assert "Not Authorized" in r.stderr


@pytest.mark.parametrize("variables", ["null", '"x"', "[]", '["ALPHA"]', "1", "true"])
@pytest.mark.parametrize("target", list(TARGETS))
@pytest.mark.parametrize("args", [(), ("--apply",)], ids=["dry-run", "apply"])
def test_variables_null_or_not_an_object_fails_closed(env, variables, target, args):
    """acdp-docs #38: {"data":{"variables":null}} must not read as "every key is new"."""
    (env.fake / "doppler.json").write_text(json.dumps({"ALPHA": "a2", "BETA_SECRET": SECRET}))
    r = env(*args, target=target, FAKE_MODE=f"vars={variables}", FAKE_FAIL_ON="variables(projectId")
    _assert_failed_closed(env.fake, r)
    assert "reading Railway variables" in r.stderr


@pytest.mark.parametrize("target", list(TARGETS))
def test_every_target_resolves_its_own_service(env, target):
    r = env(target=target)
    assert r.returncode == 0, r.stderr
    assert f"-> Railway {TARGETS[target]} (production)" in r.stderr
    assert f"doppler-keys/{target}.txt" in r.stderr


@pytest.mark.parametrize("args", [(), ("--apply",)], ids=["dry-run", "apply"])
def test_wrong_railway_token_fails_closed(env, args):
    (env.fake / "doppler.json").write_text(json.dumps({"ALPHA": "a2", "BETA_SECRET": SECRET}))
    r = env(*args, RAILWAY_API_TOKEN=TOKEN + "-but-wrong")
    _assert_failed_closed(env.fake, r)
    assert "Not Authorized" in r.stderr


def test_dry_run_reports_a_change_without_writing(env):
    (env.fake / "doppler.json").write_text(json.dumps({"ALPHA": "a2", "BETA_SECRET": SECRET}))
    r = env()
    assert r.returncode == 0, r.stderr
    assert "ALPHA\tchanged" in r.stderr and "1 key(s) would change" in r.stderr
    assert _writes(env.fake) == []
    _assert_no_leak(env.fake, r)


@pytest.mark.parametrize("args", [(), ("--apply",)], ids=["dry-run", "apply"])
def test_railway_reference_is_refused(env, args):
    (env.fake / "railway.json").write_text(
        json.dumps({"ALPHA": "${{shared.ALPHA}}", "BETA_SECRET": SECRET})
    )
    r = env(*args)
    assert r.returncode != 0
    assert "ALPHA\trailway-reference" in r.stderr and "refusing: ALPHA" in r.stderr
    assert _writes(env.fake) == []


@pytest.mark.parametrize("doppler", ["fail", "garbage", "empty"])
@pytest.mark.parametrize("args", [(), ("--apply",)], ids=["dry-run", "apply"])
def test_doppler_read_failure_fails_closed(env, doppler, args):
    r = env(*args, FAKE_DOPPLER=doppler)
    _assert_failed_closed(env.fake, r)
    assert "reading Doppler" in r.stderr


def test_failed_upsert_stops_before_the_redeploy(env):
    (env.fake / "doppler.json").write_text(json.dumps({"ALPHA": "a2", "BETA_SECRET": "b2"}))
    r = env("--apply", FAKE_MODE="errors", FAKE_FAIL_ON="variableUpsert")
    assert r.returncode != 0
    assert "setting ALPHA failed" in r.stderr and "no redeploy" in r.stderr
    assert not any("serviceInstanceRedeploy" in r["query"] for r in _requests(env.fake))
    _assert_no_leak(env.fake, r)


def test_missing_token_stops_before_any_request(env):
    r = env(RAILWAY_API_TOKEN="")
    assert r.returncode != 0 and "no Railway token" in r.stderr
    assert _requests(env.fake) == []
