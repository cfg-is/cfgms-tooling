#!/usr/bin/env python3
"""
Tests: pipeline-helper.sh lock-sweep and the pull requests it takes.

A locked pull request takes no comment from outside. The sweep locks the
pipeline's own pull requests: story and item branches, and the slice
branches of an owner-run epic (feature/epic-<N>-slice-<n>), a slice only
when its author is internal. A branch name alone is not proof: anyone can
open a pull request from a fork with that name.

The real pipeline-helper.sh runs; `gh` is a stand-in on PATH that answers
from a JSON file and logs every call.

Run: python3 scripts/tests/test-lock-sweep.py
"""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
HELPER = os.path.join(SCRIPT_DIR, "..", "pipeline-helper.sh")

GH_FAKE = r'''#!/usr/bin/env python3
import json, os, sys
world = json.load(open(os.environ["FAKE_GH_WORLD"]))
argv = sys.argv[1:]
with open(os.environ["FAKE_GH_LOG"], "a") as fh:
    fh.write(json.dumps(argv) + "\n")
text = " ".join(argv)
if argv[:2] == ["pr", "list"]:
    print(json.dumps(world["prs"]))
elif argv[:2] == ["issue", "list"]:
    print("[]")
elif argv[:2] == ["issue", "view"]:
    print(json.dumps({"labels": [{"name": n} for n in world.get("issue_labels", {}).get(argv[2], [])]}))
elif argv[:2] == ["api", "graphql"]:
    if "lockLockable" in text:
        print("{}")
    else:
        print(json.dumps({"data": {"repository": {"pullRequest": {"locked": False}}}}))
elif len(argv) > 1 and argv[0] == "api" and "/collaborators/" in argv[1]:
    login = argv[1].split("/collaborators/")[1].split("/")[0]
    perm = world.get("perms", {}).get(login)
    if perm is None:
        sys.exit(1)                      # 404: not a collaborator
    print(perm)
elif argv[:2] == ["pr", "edit"]:
    pass
else:
    sys.exit(1)
'''


def pr(number, head, login="dev", cross=False, labels=()):
    return {"number": number, "headRefName": head, "id": f"PR_node{number}",
            "labels": [{"name": n} for n in labels], "author": {"login": login},
            "isCrossRepository": cross}


class LockSweep(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="lock-sweep-"))
        (self.root / "bin").mkdir()
        gh = self.root / "bin" / "gh"
        gh.write_text(GH_FAKE)
        gh.chmod(0o755)
        self.world = self.root / "world.json"
        self.log = self.root / "gh.log"

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def sweep(self, prs, perms=None, issue_labels=None):
        # perms: what the real API gives in `.permission`: admin, write, read or none
        self.world.write_text(json.dumps({"prs": prs, "perms": perms or {"dev": "write"},
                                          "issue_labels": issue_labels or {}}))
        self.log.write_text("")
        env = dict(os.environ, PATH="%s%s%s" % (self.root / "bin", os.pathsep, os.environ["PATH"]),
                   FAKE_GH_WORLD=str(self.world), FAKE_GH_LOG=str(self.log))
        r = subprocess.run(["bash", HELPER, "lock-sweep"], capture_output=True, text=True, env=env,
                           timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        calls = [json.loads(l) for l in self.log.read_text().splitlines()]
        locked = sorted(a.split("l=")[1] for c in calls if "lockLockable" in " ".join(c)
                        for a in c if a.startswith("l="))
        labelled = {int(c[2]): c[c.index("--add-label") + 1] for c in calls if c[:2] == ["pr", "edit"]}
        return r.stdout, locked, labelled

    def test_a_slice_of_an_internal_author_is_locked_and_labelled(self):
        out, locked, labelled = self.sweep([pr(55, "feature/epic-7-slice-1")])
        self.assertEqual(locked, ["PR_node55"])
        self.assertEqual(labelled, {55: "internal"})
        self.assertIn("LOCKED_PR:#55", out)
        self.assertIn("LOCK_SWEEP_DONE:1", out)

    def test_story_and_item_branches_are_taken_as_before(self):
        out, locked, labelled = self.sweep(
            [pr(1, "feature/story-12-agent"), pr(2, "feature/item-abcdef123456-agent"),
             pr(3, "fix/something"), pr(4, "feature/epic-7-notes")])
        self.assertEqual(locked, ["PR_node1", "PR_node2"])
        self.assertEqual(sorted(labelled), [1, 2])

    def test_a_slice_branch_name_from_a_fork_is_not_taken(self):
        out, locked, labelled = self.sweep([pr(55, "feature/epic-7-slice-1", cross=True)])
        self.assertEqual((locked, labelled), ([], {}))
        self.assertIn("LOCK_SKIPPED_PR:#55", out)

    def test_a_slice_branch_name_from_an_author_who_cannot_push_is_not_taken(self):
        # read (also the answer for triage), none, no answer; and the values
        # that the field never has (role names) are not taken either
        for perms in ({"dev": "read"}, {"dev": "none"}, {}, {"dev": "push"}, {"dev": "maintain"}):
            with self.subTest(perms=perms):
                out, locked, labelled = self.sweep([pr(55, "feature/epic-7-slice-1")],
                                                   perms=perms or {"other": "admin"})
                self.assertEqual((locked, labelled), ([], {}))

    def test_a_slice_with_no_author_or_no_fork_answer_is_not_taken(self):
        ghost = pr(55, "feature/epic-7-slice-1")
        ghost["author"] = None
        unknown = pr(56, "feature/epic-7-slice-2")
        del unknown["isCrossRepository"]
        out, locked, labelled = self.sweep([ghost, unknown])
        self.assertEqual((locked, labelled), ([], {}))

    def test_a_name_that_only_starts_like_a_slice_is_not_taken(self):
        out, locked, labelled = self.sweep(
            [pr(55, "feature/epic-7-slice-1-extra"), pr(56, "feature/epic-0-slice-1"),
             pr(57, "xfeature/epic-7-slice-1")])
        self.assertEqual((locked, labelled), ([], {}))

    def test_write_and_admin_authors_are_internal(self):
        """A maintainer's `.permission` is `write` in the real API."""
        out, locked, labelled = self.sweep(
            [pr(55, "feature/epic-7-slice-1", login="a"), pr(56, "feature/epic-7-slice-2", login="m")],
            perms={"a": "admin", "m": "write"})
        self.assertEqual(locked, ["PR_node55", "PR_node56"])

    def test_a_slice_gets_the_capability_tags_of_its_epic(self):
        out, locked, labelled = self.sweep([pr(55, "feature/epic-7-slice-1", labels=["internal"])],
                                           issue_labels={"7": ["epic", "cap:web", "cap:msp"]})
        self.assertEqual(labelled, {55: "cap:web,cap:msp"})
        self.assertEqual(locked, ["PR_node55"])


if __name__ == "__main__":
    unittest.main()
