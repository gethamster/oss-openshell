#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 Hamster
# SPDX-License-Identifier: Apache-2.0

"""Exercise the status bridge with a local GitHub API fixture, without credentials."""

import copy
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REPO = "gethamster/oss-openshell"
SHA = "a" * 40
PREFIX = f"repos/{REPO}"
FAKE_GH = r"""#!/usr/bin/env python3
import json, os, subprocess, sys
args = sys.argv[1:]
path = next(arg for arg in args if arg.startswith("repos/"))
if "/statuses/" in path:
    fields = {args[i+1].split("=", 1)[0]: args[i+1].split("=", 1)[1]
              for i, value in enumerate(args) if value == "-f"}
    fields["sha"] = path.rsplit("/", 1)[1]
    with open(os.environ["STATUS_FILE"], "a") as out:
        out.write(json.dumps(fields) + "\n")
    print("{}")
    sys.exit(0)
with open(os.environ["API_FILE"]) as source:
    value = json.load(source).get(path)
if value is None:
    print("Unexpected API path: " + path, file=sys.stderr)
    sys.exit(1)
data = json.dumps(value)
if "--jq" in args:
    subprocess.run(["jq", "-r", args[args.index("--jq") + 1]],
                   input=data, text=True, check=True)
else:
    print(data)
"""


def fixtures():
    result = {
        f"{PREFIX}/pulls/14": {"state": "open", "head": {"sha": SHA}},
        f"{PREFIX}/issues/14": {"labels": []},
        f"{PREFIX}/collaborators/maintainer/permission": {"permission": "write"},
    }
    for index, name in enumerate(("branch-checks.yml", "helm-lint.yml"), 1):
        result[
            f"{PREFIX}/actions/workflows/{name}/runs?head_sha={SHA}&event=workflow_dispatch&per_page=100"
        ] = {
            "workflow_runs": [
                {
                    "id": index,
                    "event": "workflow_dispatch",
                    "head_sha": SHA,
                    "head_repository": {"full_name": REPO},
                    "head_branch": "candidate",
                    "actor": {"login": "maintainer"},
                    "status": "completed",
                    "conclusion": "success",
                    "created_at": "2026-11-02T00:00:00Z",
                    "html_url": f"https://example.test/runs/{index}",
                }
            ]
        }
        result[f"{PREFIX}/actions/runs/{index}/jobs?per_page=10"] = {
            "jobs": [{"name": "Required tests", "conclusion": "success"}]
        }
    return result


class RequiredCiGatesTests(unittest.TestCase):
    def evaluate(self, api, **overrides):
        workflow = (ROOT / ".github/workflows/required-ci-gates.yml").read_text()
        script = workflow.split("        run: |\n", 1)[1]
        script = "\n".join(
            line[10:] if line.startswith("          ") else line
            for line in script.splitlines()
        )
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / "gh").write_text(FAKE_GH)
            (base / "gh").chmod(0o755)
            (base / "api.json").write_text(json.dumps(api))
            env = dict(
                os.environ,
                PATH=f"{base}:{os.environ['PATH']}",
                API_FILE=str(base / "api.json"),
                STATUS_FILE=str(base / "statuses"),
                GH_REPO=REPO,
                FORK_NATIVE_CI="true",
                EVENT_NAME="workflow_dispatch",
                DISPATCH_PR_NUMBER="14",
            )
            env.update(overrides)
            completed = subprocess.run(
                ["bash", "-c", script], env=env, capture_output=True, text=True
            )
            self.assertEqual(
                completed.returncode, 0, completed.stderr + completed.stdout
            )
            status_file = base / "statuses"
            return (
                [json.loads(line) for line in status_file.read_text().splitlines()]
                if status_file.exists()
                else []
            )

    def branch(self, api):
        return api[
            f"{PREFIX}/actions/workflows/branch-checks.yml/runs?head_sha={SHA}&event=workflow_dispatch&per_page=100"
        ]["workflow_runs"][0]

    def test_exact_head_success_requires_real_jobs(self):
        statuses = self.evaluate(fixtures())
        self.assertTrue(
            all(
                status["state"] == "success" and status["sha"] == SHA
                for status in statuses
            )
        )
        self.assertEqual(len(statuses), 4)

    def test_stale_wrong_repository_and_wrong_event_cannot_satisfy(self):
        for field, value in (
            ("head_sha", "b" * 40),
            ("head_repository", {"full_name": "other/repo"}),
            ("event", "pull_request"),
        ):
            with self.subTest(field=field):
                api = fixtures()
                self.branch(api)[field] = value
                self.assertEqual(self.evaluate(api)[0]["state"], "pending")

    def test_read_only_dispatcher_cannot_satisfy(self):
        api = fixtures()
        api[f"{PREFIX}/collaborators/maintainer/permission"] = {"permission": "read"}
        self.assertEqual(self.evaluate(api)[0]["state"], "failure")

    def test_pending_run_does_not_reuse_previous_success(self):
        api = fixtures()
        pending = copy.deepcopy(self.branch(api))
        pending.update(
            id=10, status="queued", conclusion=None, created_at="2026-11-02T01:00:00Z"
        )
        key = f"{PREFIX}/actions/workflows/branch-checks.yml/runs?head_sha={SHA}&event=workflow_dispatch&per_page=100"
        api[key]["workflow_runs"].append(pending)
        self.assertEqual(self.evaluate(api)[0]["state"], "pending")

    def test_helm_requires_the_same_head(self):
        api = fixtures()
        key = f"{PREFIX}/actions/workflows/helm-lint.yml/runs?head_sha={SHA}&event=workflow_dispatch&per_page=100"
        api[key]["workflow_runs"][0]["head_sha"] = "b" * 40
        statuses = self.evaluate(api)
        self.assertEqual(statuses[0]["state"], "success")
        self.assertEqual(statuses[-1]["state"], "pending")

    def test_named_e2e_job_cannot_be_skipped(self):
        api = fixtures()
        api[f"{PREFIX}/issues/14"]["labels"] = [{"name": "test:e2e"}]
        key = f"{PREFIX}/actions/workflows/branch-e2e.yml/runs?head_sha={SHA}&event=workflow_dispatch&per_page=100"
        api[key] = copy.deepcopy(
            api[
                f"{PREFIX}/actions/workflows/helm-lint.yml/runs?head_sha={SHA}&event=workflow_dispatch&per_page=100"
            ]
        )
        api[key]["workflow_runs"][0]["id"] = 3
        api[f"{PREFIX}/actions/runs/3/jobs?per_page=10"] = {
            "jobs": [
                {
                    "name": "Core E2E result",
                    "status": "completed",
                    "conclusion": "skipped",
                }
            ]
        }
        statuses = self.evaluate(api)
        self.assertEqual(statuses[1]["context"], "OpenShell / E2E")
        self.assertEqual(statuses[1]["state"], "pending")

    def test_failed_cancelled_and_skipped_runs_cannot_satisfy(self):
        for conclusion in ("failure", "cancelled", "skipped"):
            with self.subTest(conclusion=conclusion):
                api = fixtures()
                self.branch(api)["conclusion"] = conclusion
                self.assertEqual(self.evaluate(api)[0]["state"], "failure")

    def test_newest_failed_run_supersedes_earlier_success(self):
        api = fixtures()
        failed = copy.deepcopy(self.branch(api))
        failed.update(id=10, conclusion="failure", created_at="2026-11-02T01:00:00Z")
        key = f"{PREFIX}/actions/workflows/branch-checks.yml/runs?head_sha={SHA}&event=workflow_dispatch&per_page=100"
        api[key]["workflow_runs"].append(failed)
        self.assertEqual(self.evaluate(api)[0]["state"], "failure")

    def test_empty_or_metadata_only_jobs_cannot_satisfy(self):
        for jobs in ([], [{"name": "Resolve PR metadata", "conclusion": "success"}]):
            api = fixtures()
            api[f"{PREFIX}/actions/runs/1/jobs?per_page=10"] = {"jobs": jobs}
            self.assertEqual(self.evaluate(api)[0]["state"], "failure")

    def test_stale_completion_does_not_publish_against_current_head(self):
        api = fixtures()
        api[f"{PREFIX}/commits/{'b' * 40}/pulls"] = [
            {"number": 14, "state": "open", "head": {"sha": SHA}}
        ]
        self.assertEqual(
            self.evaluate(
                api,
                EVENT_NAME="workflow_run",
                WORKFLOW_RUN_EVENT="workflow_dispatch",
                WORKFLOW_RUN_HEAD_SHA="b" * 40,
                WORKFLOW_RUN_HEAD_BRANCH="candidate",
            ),
            [],
        )

    def test_upstream_still_requires_its_current_mirror(self):
        api = fixtures()
        api[f"{PREFIX}/branches/pull-request/14"] = {"commit": {"sha": "b" * 40}}
        statuses = self.evaluate(
            api,
            FORK_NATIVE_CI="false",
            EVENT_NAME="pull_request_target",
            PR_NUMBER_FROM_EVENT="14",
            PR_HEAD_SHA_FROM_EVENT=SHA,
            PR_LABELS_FROM_EVENT="[]",
        )
        self.assertEqual(statuses[0]["state"], "pending")
        self.assertIn("mirror", statuses[0]["description"])


if __name__ == "__main__":
    unittest.main()
