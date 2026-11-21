#!/usr/bin/env python3
"""
Tests: slice submit requests (devcontainer/fsm/slice-submit, scripts/fsm/submit.py).

  * the real `slice-submit` command and the supervisor's reader agree: a
    request written by the command is read as a Request, the command returns
    when the answer for ITS request id is there, and not before;
  * wrong arguments write nothing;
  * the reader never follows a link the owner planted, never blocks on a
    FIFO, and caps every read;
  * a request is handled once, also across a supervisor restart.

Run: python3 .claude/tooling/scripts/tests/test-fsm-submit.py
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import fsm_testlib  # noqa: E402,F401  (puts scripts/fsm on sys.path)

import state  # noqa: E402
import submit  # noqa: E402

COMMAND = Path(__file__).resolve().parents[2] / "devcontainer" / "fsm" / "slice-submit"
BASE = "a" * 40
RID = "0123456789abcdef0123456789abcdef"


class Case(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="fsm-submit-"))
        self.out = self.tmp / "out"
        self.ctx = self.tmp / "context"
        self.out.mkdir()
        self.ctx.mkdir()
        self.claim = self.tmp / "claim.md"
        self.claim.write_text("# Slice 1\nDelivers the thing.\n")
        self.secret = self.tmp / "host-secret"
        self.secret.write_text("HOST-SECRET-VALUE\n")
        # The owner's workspace: a branch that starts at the develop commit.
        self.ws = self.tmp / "ws"
        self.ws.mkdir()
        self.git("init", "-q", "-b", "feature/epic")
        (self.ws / "a.txt").write_text("one\n")
        self.git("add", "a.txt")
        self.git("commit", "-qm", "develop 0")
        self.base = self.git("rev-parse", "HEAD")
        self.git("update-ref", "refs/remotes/origin/develop", self.base)

    def git(self, *args, check=True):
        env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", HOME=str(self.tmp))
        proc = subprocess.run(["/usr/bin/git", "-C", str(self.ws), "-c", "user.name=t",
                               "-c", "user.email=t@t", *args], env=env, capture_output=True, text=True)
        if check and proc.returncode != 0:
            self.fail(f"git {args}: {proc.stderr}")
        return proc.stdout.strip()

    def develop_moves(self, path="d.txt", text="develop\n"):
        """A new commit on origin/develop that the workspace has fetched and
        not merged. Returns its id."""
        self.git("checkout", "-q", "--detach", "refs/remotes/origin/develop")
        (self.ws / path).write_text(text)
        self.git("add", path)
        self.git("commit", "-qm", f"develop: {path}")
        new = self.git("rev-parse", "HEAD")
        self.git("update-ref", "refs/remotes/origin/develop", new)
        self.git("checkout", "-q", "feature/epic")
        return new

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def command(self, *args, wait=20):
        env = dict(os.environ, CFGMS_FSM_OUT=str(self.out), CFGMS_FSM_CONTEXT=str(self.ctx),
                   CFGMS_FSM_WORKSPACE=str(self.ws), GIT_CONFIG_NOSYSTEM="1", HOME=str(self.tmp))
        return subprocess.Popen([sys.executable, "-I", str(COMMAND), "--wait", str(wait), *args],
                                env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def std_args(self, slice_no=1, **over):
        a = {"--slice": str(slice_no), "--claim": str(self.claim),
             "--subject": "fsm: add the thing"}
        a.update(over)
        return [x for kv in a.items() for x in kv]

    def wait_for_request(self, n=1, secs=10):
        end = time.time() + secs
        while time.time() < end:
            found = submit.scan(self.out).requests
            if len(found) >= n:
                return found
            time.sleep(0.05)
        self.fail("no request appeared")

    def request_dir(self, name, *, request=None, subject="fsm: add the thing\n", claim="c\n"):
        d = self.out / "submit" / name
        d.mkdir(parents=True)
        if request is not None:
            (d / "request.json").write_text(request if isinstance(request, str)
                                            else json.dumps(request))
        if subject is not None:
            (d / "subject.txt").write_text(subject)
        if claim is not None:
            (d / "claim.md").write_text(claim)
        return d

    def req(self, slice_no=1, **over):
        r = {"slice": slice_no, "request_id": RID, "base": BASE, "base_from": "git",
             "builds_on": 0}
        r.update(over)
        return r


class TestCommandAndReader(Case):
    def test_round_trip_accepted(self):
        p = self.command(*self.std_args(), "--builds-on", "0")
        (r,) = self.wait_for_request()
        self.assertIsInstance(r, submit.Request)
        self.assertEqual((r.dirname, r.slice, r.base, r.builds_on, r.subject),
                         ("1-1", 1, self.base, 0, "fsm: add the thing"))
        self.assertEqual(r.claim, self.claim.read_text())
        self.assertIsNone(p.poll(), "the command must wait for the answer")
        submit.write_answer(self.ctx, 1, r.request_id, accepted=True, round_no=1, files=42)
        out, err = p.communicate(timeout=10)
        self.assertEqual(p.returncode, 0, err)
        self.assertIn("slice 1 round 1: snapshot taken (42 files)", out)

    def test_refused_prints_the_reason_and_exits_1(self):
        p = self.command(*self.std_args(slice_no=2), "--builds-on", "1")
        (r,) = self.wait_for_request()
        self.assertEqual((r.slice, r.builds_on), (2, 1))
        submit.write_answer(self.ctx, 2, r.request_id, accepted=False,
                            reason="--builds-on 1: no such slice has been submitted")
        _, err = p.communicate(timeout=10)
        self.assertEqual(p.returncode, 1)
        self.assertIn("REFUSED: --builds-on 1: no such slice", err)

    def test_an_answer_for_another_request_does_not_release_the_command(self):
        submit.write_answer(self.ctx, 1, RID, accepted=True, round_no=1)   # an old round's answer
        p = self.command(*self.std_args(), wait=2)
        _, err = p.communicate(timeout=40)
        self.assertEqual(p.returncode, 3)
        self.assertIn("no answer from the supervisor after 2 seconds. The request was withdrawn",
                      err)
        # nothing is left for a supervisor that comes back later
        self.assertEqual(os.listdir(self.out / "submit"), [])
        self.assertEqual(submit.scan(self.out).requests, [])

    def test_an_answer_that_comes_just_after_the_time_limit_is_still_reported(self):
        # the supervisor read the request before the command gave up, and
        # answers while the command is in its short wait after the withdrawal
        p = self.command(*self.std_args(), wait=2)
        (r,) = self.wait_for_request()
        end = time.time() + 20
        while (self.out / "submit" / "1-1").exists() and time.time() < end:
            time.sleep(0.05)
        self.assertFalse((self.out / "submit" / "1-1").exists(), "the request was not withdrawn")
        self.assertEqual(submit.scan(self.out).requests, [])     # a withdrawn name is no request
        submit.write_answer(self.ctx, 1, r.request_id, accepted=True, round_no=1, files=3)
        out, err = p.communicate(timeout=30)
        self.assertEqual(p.returncode, 0, err)
        self.assertIn("snapshot taken (3 files)", out)
        self.assertEqual(os.listdir(self.out / "submit"), [])

    def test_an_answered_request_is_removed_and_its_name_is_free_again(self):
        seen = set()
        for _round in (1, 2):
            p = self.command(*self.std_args())
            (r,) = self.wait_for_request()
            self.assertEqual(r.dirname, "1-1")
            self.assertNotIn(r.request_id, seen)      # a new id each time: never "seen" twice
            seen.add(r.request_id)
            submit.write_answer(self.ctx, 1, r.request_id, accepted=True, round_no=1)
            p.communicate(timeout=10)
            self.assertEqual(p.returncode, 0)
            self.assertEqual(os.listdir(self.out / "submit"), [])

    def test_two_requests_of_one_slice_at_the_same_time_get_two_names(self):
        p1 = self.command(*self.std_args())
        self.wait_for_request()
        p2 = self.command(*self.std_args())
        found = self.wait_for_request(2)
        self.assertEqual([r.dirname for r in found], ["1-1", "1-2"])
        for p in (p1, p2):
            p.kill()
            p.communicate()

    def test_wrong_arguments_exit_2_and_write_nothing(self):
        big = self.tmp / "big.md"
        big.write_bytes(b"x" * (64 * 1024 + 1))
        empty = self.tmp / "empty.md"
        empty.write_text(" \n")
        bad = [
            self.std_args(slice_no=0),
            self.std_args(slice_no=1000),
            self.std_args(**{"--subject": "No Scope Here"}),
            self.std_args(**{"--subject": "fsm: a\nFixes #1"}),
            self.std_args(**{"--subject": "fsm: " + "x" * 150}),
            self.std_args(**{"--claim": str(self.tmp / "absent.md")}),
            self.std_args(**{"--claim": str(big)}),
            self.std_args(**{"--claim": str(empty)}),
            self.std_args() + ["--builds-on", "1"],          # itself
            self.std_args()[:-2],                            # no --subject
        ]
        for args in bad:
            p = self.command(*args, wait=1)
            p.communicate(timeout=10)
            self.assertEqual(p.returncode, 2, args)
        self.assertFalse((self.out / "submit").exists() and any((self.out / "submit").iterdir()))

    def test_half_written_request_is_not_seen(self):
        self.request_dir(".1-abc.tmp", request=self.req())
        s = submit.scan(self.out)
        self.assertEqual((s.requests, s.ignored, s.problem), ([], [], ""))


class TestBaseFromGit(Case):
    """The base of a request is what git in the workspace says, never what
    the owner types. The supervisor measures the slice against it."""

    def submitted(self, *extra):
        """(base in the request, what the command printed) of one accepted submit."""
        p = self.command(*self.std_args(), *extra)
        (r,) = self.wait_for_request()
        submit.write_answer(self.ctx, 1, r.request_id, accepted=True, round_no=1)
        out, err = p.communicate(timeout=10)
        self.assertEqual(p.returncode, 0, err)
        return r.base, out + err

    def refused_by_the_command(self, text):
        p = self.command(*self.std_args(), wait=1)
        _, err = p.communicate(timeout=10)
        self.assertEqual(p.returncode, 2, err)
        self.assertIn(text, err)
        self.assertIn("No request was sent.", err)
        self.assertFalse((self.out / "submit").exists() and any((self.out / "submit").iterdir()))

    NOT_MERGED = "git has no merge of it"

    def test_a_workspace_that_did_not_fetch_is_on_the_commit_it_started_from(self):
        (self.ws / "mine.txt").write_text("work, not committed\n")
        self.assertEqual(self.submitted()[0], self.base)
        self.git("add", "mine.txt")
        self.git("commit", "-qm", "work")
        self.assertEqual(self.submitted()[0], self.base)

    def test_what_is_fetched_must_be_merged(self):
        (self.ws / "mine.txt").write_text("work\n")
        self.git("add", "mine.txt")
        self.git("commit", "-qm", "work")
        new = self.develop_moves()                           # fetched, not merged
        self.refused_by_the_command(f"has fetched origin/develop commit {new[:12]} and "
                                    f"{self.NOT_MERGED}: in git, {self.ws} is built on develop "
                                    f"commit {self.base[:12]}")
        self.git("merge", "-q", "--no-edit", "refs/remotes/origin/develop")
        self.assertEqual(self.submitted()[0], new)
        self.develop_moves("e.txt")
        self.refused_by_the_command(self.NOT_MERGED)

    def test_a_squash_merge_of_develop_is_not_a_merge(self):
        # the files of develop, also inside a file the owner changed after,
        # and no merge commit
        (self.ws / "mine.txt").write_text("work\n")
        self.git("add", "mine.txt")
        self.git("commit", "-qm", "work")
        new = self.develop_moves("a.txt", "one\ndevelop\n")
        self.git("merge", "-q", "--squash", "refs/remotes/origin/develop")
        (self.ws / "a.txt").write_text("one\ndevelop\nmine\n")
        self.git("add", "a.txt")
        self.git("commit", "-qm", "develop, squashed, and my line")
        self.refused_by_the_command(self.NOT_MERGED)
        # the real merge meets the squashed lines again: the owner repairs it
        self.git("merge", "-q", "--no-edit", "refs/remotes/origin/develop", check=False)
        self.refused_by_the_command("a merge in")
        (self.ws / "a.txt").write_text("one\ndevelop\nmine\n")
        self.git("add", "a.txt")
        self.git("commit", "-qm", "merge develop")
        self.assertEqual(self.submitted()[0], new)

    def test_a_merge_of_an_older_develop_commit_than_the_fetched_one_is_refused(self):
        older = self.develop_moves()
        self.develop_moves("e.txt")
        self.git("merge", "-q", "--no-edit", older)
        self.refused_by_the_command(self.NOT_MERGED)

    def test_a_typed_base_is_not_used(self):
        other = "b" * 40
        base, text = self.submitted("--base", other)
        self.assertEqual(base, self.base)
        self.assertIn(f"--base {other[:12]} is not used. /workspace is built on origin/develop "
                      f"commit {self.base[:12]}", text)
        _, text = self.submitted("--base", self.base)
        self.assertNotIn("is not used", text)

    def test_a_merge_that_is_not_finished_is_refused(self):
        (self.ws / "a.txt").write_text("mine\n")
        self.git("add", "a.txt")
        self.git("commit", "-qm", "work")
        self.develop_moves("a.txt", "theirs\n")
        self.git("merge", "-q", "--no-edit", "refs/remotes/origin/develop", check=False)
        self.assertTrue(self.git("rev-parse", "-q", "--verify", "MERGE_HEAD"))
        self.refused_by_the_command("a merge in")
        # the conflict is repaired and the merge is not committed: the same
        (self.ws / "a.txt").write_text("both\n")
        self.git("add", "a.txt")
        self.refused_by_the_command("a merge in")
        self.git("commit", "-qm", "merge develop")
        self.assertEqual(self.submitted()[0], self.git("rev-parse", "refs/remotes/origin/develop"))

    def test_a_rebase_that_stopped_with_no_conflict_is_refused(self):
        # `break`, or an `exec` that failed: git has no REBASE_HEAD then
        (self.ws / "mine.txt").write_text("work\n")
        self.git("add", "mine.txt")
        self.git("commit", "-qm", "work")
        (self.ws / "more.txt").write_text("more\n")
        self.git("add", "more.txt")
        self.git("commit", "-qm", "more work")
        new = self.develop_moves()
        self.git("rebase", "-x", "false", "refs/remotes/origin/develop", check=False)
        self.assertFalse(self.git("rev-parse", "-q", "--verify", "REBASE_HEAD", check=False))
        self.refused_by_the_command("a rebase in")
        self.git("rebase", "--abort")
        self.git("rebase", "-q", "refs/remotes/origin/develop")      # a finished rebase is a catch-up
        self.assertEqual(self.submitted()[0], new)

    def test_a_rebase_that_stopped_at_a_conflict_and_was_finished_is_taken(self):
        # git leaves REBASE_HEAD behind then; it does not say a rebase is open
        (self.ws / "a.txt").write_text("mine\n")
        self.git("add", "a.txt")
        self.git("commit", "-qm", "work")
        new = self.develop_moves("a.txt", "theirs\n")
        self.git("rebase", "refs/remotes/origin/develop", check=False)
        self.refused_by_the_command("a rebase in")
        (self.ws / "a.txt").write_text("both\n")
        self.git("add", "a.txt")
        self.git("-c", "core.editor=true", "rebase", "--continue")
        self.assertTrue(self.git("rev-parse", "-q", "--verify", "REBASE_HEAD", check=False),
                        "this git leaves no REBASE_HEAD; the test proves nothing")
        self.assertEqual(self.submitted()[0], new)

    def test_a_cherry_pick_or_a_revert_that_is_not_finished_is_refused(self):
        (self.ws / "a.txt").write_text("mine\n")
        self.git("add", "a.txt")
        self.git("commit", "-qm", "work")
        self.git("revert", "--no-commit", "HEAD")
        self.refused_by_the_command("a revert in")
        self.git("revert", "--abort")
        self.git("checkout", "-q", "-b", "side", self.base)
        (self.ws / "a.txt").write_text("other\n")
        self.git("add", "a.txt")
        self.git("commit", "-qm", "side work")
        self.git("checkout", "-q", "feature/epic")
        self.git("cherry-pick", "side", check=False)
        self.refused_by_the_command("a cherry-pick in")
        self.git("cherry-pick", "--abort")
        self.assertEqual(self.submitted()[0], self.base)

    def test_a_branch_with_the_name_of_a_git_state_file_is_not_an_open_merge(self):
        self.git("branch", "MERGE_HEAD")
        self.assertEqual(self.submitted()[0], self.base)

    def test_a_workspace_with_no_origin_develop_is_refused(self):
        self.git("update-ref", "-d", "refs/remotes/origin/develop")
        self.refused_by_the_command("has no origin/develop")

    def test_a_workspace_that_is_no_git_repository_is_refused(self):
        shutil.rmtree(self.ws / ".git")
        self.refused_by_the_command("has no HEAD commit")

    def test_the_reader_takes_only_a_base_that_was_read_from_git(self):
        old_tool = self.req()
        del old_tool["base_from"]
        self.request_dir("1-1", request=old_tool)
        self.request_dir("2-1", request=self.req(2, base_from="owner", request_id="f" * 32))
        got = submit.scan(self.out).requests
        self.assertEqual([type(r) for r in got], [submit.Refused, submit.Refused])
        for r in got:
            self.assertIn("this slice-submit is an old version", r.reason)


class TestReaderIsSafe(Case):
    def test_valid_request(self):
        self.request_dir("3-7", request=self.req(3, builds_on=2))
        (r,) = submit.scan(self.out).requests
        self.assertEqual(r, submit.Request("3-7", 3, RID, BASE, 2, "fsm: add the thing", "c\n"))

    def test_no_out_submit_directory_is_an_empty_scan(self):
        s = submit.scan(self.out)
        self.assertEqual((s.requests, s.ignored, s.problem), ([], [], ""))

    def test_submit_directory_that_is_a_link_is_not_followed(self):
        real = self.tmp / "elsewhere"
        (real / "1-1").mkdir(parents=True)
        (real / "1-1" / "request.json").write_text(json.dumps(self.req()))
        os.symlink(real, self.out / "submit")
        s = submit.scan(self.out)
        self.assertEqual(s.requests, [])
        self.assertIn("not a plain directory", s.problem)

    def test_request_directory_that_is_a_link_is_ignored(self):
        real = self.request_dir("9-9", request=self.req(9))
        os.rename(real, self.tmp / "moved")
        os.symlink(self.tmp / "moved", self.out / "submit" / "1-1")
        s = submit.scan(self.out)
        self.assertEqual(s.requests, [])
        self.assertEqual([n for n, _ in s.ignored], ["1-1"])

    def test_linked_files_are_never_read(self):
        d = self.request_dir("1-1", request=self.req(), claim=None)
        os.symlink(self.secret, d / "claim.md")
        (r,) = submit.scan(self.out).requests
        self.assertEqual(r, submit.Refused("1-1", 1, RID, "claim.md: symlink"))

        d2 = self.request_dir("2-1", request=self.req(2), subject=None)
        os.symlink(self.secret, d2 / "subject.txt")
        r2 = [x for x in submit.scan(self.out).requests if x.slice == 2][0]
        self.assertEqual(r2.reason, "subject.txt: symlink")

        d3 = self.request_dir("3-1", request=None)
        os.symlink(self.secret, d3 / "request.json")
        s = submit.scan(self.out)
        self.assertIn(("3-1", "request.json: symlink"), s.ignored)
        self.assertNotIn("HOST-SECRET", repr(s))

    def test_a_fifo_does_not_block_the_supervisor(self):
        d = self.request_dir("1-1", request=self.req(), claim=None)
        os.mkfifo(d / "claim.md")
        done = []
        t = threading.Thread(target=lambda: done.append(submit.scan(self.out)), daemon=True)
        t.start()
        t.join(5)
        self.assertTrue(done, "scan blocked on a FIFO")
        self.assertEqual(done[0].requests[0].reason, "claim.md: not_regular")

    def test_reads_are_capped(self):
        self.request_dir("1-1", request=self.req(), claim="x" * (submit.CLAIM_CAP + 1))
        self.request_dir("2-1", request=self.req(2), subject="fsm: " + "y" * submit.SUBJECT_CAP)
        self.request_dir("3-1", request=json.dumps(self.req(3)) + " " * submit.REQUEST_CAP)
        s = submit.scan(self.out)
        self.assertEqual({r.slice: r.reason for r in s.requests},
                         {1: "claim.md: too_large", 2: "subject.txt: too_large"})
        self.assertEqual(s.ignored, [("3-1", "request.json: too_large")])

    def test_field_checks(self):
        cases = [
            (self.req(2), "request.json names a different slice than its directory"),
            (self.req(True), "request.json names a different slice than its directory"),
            (self.req(base="abc"), "the base must be a full 40-character commit id"),
            (self.req(base=BASE + "\n"), "the base must be a full 40-character commit id"),
            (self.req(builds_on="2"), "--builds-on must be a slice number"),
            (self.req(builds_on=-1), "--builds-on must be a slice number"),
            (self.req(builds_on=True), "--builds-on must be a slice number"),
            (self.req(builds_on=1), "slice 1 cannot build on itself"),
        ]
        for i, (request, reason) in enumerate(cases, 1):
            shutil.rmtree(self.out / "submit", ignore_errors=True)
            self.request_dir(f"1-{i}", request=request)
            (r,) = submit.scan(self.out).requests
            self.assertEqual((type(r), r.reason), (submit.Refused, reason), request)

    def test_subject_checks(self):
        ok = submit.validate_subject("controller/api: persist the hostname\n")
        self.assertEqual(ok, "controller/api: persist the hostname")
        for bad in (None, "", "   ", "fsm: a\nFixes #12", "fsm: a\r\nb", "Fsm: upper scope",
                    "no colon here", "fsm:", "fsm: " + "x" * 150, "fsm: bell\x07",
                    "fsm: add the thing (Issue #12)", "fsm: add the thing (Epic #900)",
                    # text that acts on GitHub
                    "fsm: x [skip ci]", "fsm: x [ci skip]", "fsm: x [no ci]", "fsm: x [skip actions]",
                    "fsm: x [CI Skip]", "fsm: x skip-checks: true",
                    "fsm: x fixes #1", "fsm: x (issue #5)", "fsm: x (#5)", "fsm: see org/repo#7",
                    "fsm: see https://github.com/o/r/issues/7", "fsm: @everyone look",
                    "fsm: closes GH-12", "fsm: Fixes gh-12", "fsm: see github.com/o/r/pull/7",
                    "fsm: see www.example.com", "fsm: get ftp://host/x", "fsm: see o/r#7",
                    "fsm: See HTTPS://x.example", "fsm: bump @types/node", "fsm: x [ skip  ci ]",
                    "fsm: x [actions skip]", "--help: x", "-x: y", "fsm: x (#5).",
                    # not printable ASCII
                    "fsm: a\u202eevil", "fsm: a\x85b", "fsm: a\x9bb", "fsm: \ufeffx", "fsm: caf\u00e9",
                    "fsm: a\u2028b", "fsm: a\x7fb"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                submit.validate_subject(bad)
        for good in ("fsm: handle list[0] and a/b paths", "docs: say what C# is not",
                     "api: keep e-mail user@ unchanged", "cert: support PKCS#12 bundles",
                     "api: accept user@example.com as login", "docs: describe the [no] default",
                     "storage: fix users[ci] index", "docs: fix a/b#c anchor",
                     "ci: skip nothing", "fsm: the no-ci case"):
            self.assertEqual(submit.validate_subject(good), good)

    def test_deeply_nested_json_is_not_a_crash(self):
        self.request_dir("1-1", request="[" * 3900)
        s = submit.scan(self.out)
        self.assertEqual((s.requests, s.ignored), ([], [("1-1", "request.json: not JSON")]))

    def test_a_file_that_grows_after_the_size_check_is_cut_off(self):
        # the size is checked first; the read stops at the cap whatever the size said
        (self.out / "big").mkdir(parents=True)
        (self.out / "big" / "f").write_bytes(b"x" * 5000)
        real = os.fstat

        class Small:
            st_mode = 0o100644
            st_size = 10
        os.fstat = lambda fd: Small()
        try:
            dfd = os.open(self.out / "big", os.O_RDONLY)
            try:
                self.assertEqual(submit._read_at(dfd, "f", 4096), (None, "too_large"))
            finally:
                os.close(dfd)
        finally:
            os.fstat = real

    def test_slice_must_be_an_integer(self):
        self.request_dir("1-1", request=self.req(1.0))
        self.request_dir("1-2", request=self.req(True))
        got = submit.scan(self.out).requests
        self.assertEqual([type(r) for r in got], [submit.Refused, submit.Refused])

    def test_request_id_must_be_exactly_32_hex(self):
        self.request_dir("1-1", request=self.req(request_id="a" * 32 + "\n"))
        self.request_dir("1-2", request=self.req(request_id="a" * 33))
        s = submit.scan(self.out)
        self.assertEqual((s.requests, sorted(n for n, _ in s.ignored)), ([], ["1-1", "1-2"]))

    def test_seen_is_a_pair_of_directory_and_request_id(self):
        self.request_dir("1-1", request=self.req(request_id="a" * 32))
        self.request_dir("1-2", request=self.req(request_id="a" * 32))    # an old id, a new directory
        s = submit.scan(self.out, {("1-1", "a" * 32)})
        self.assertEqual([r.dirname for r in s.requests], ["1-2"])

    def test_empty_claim_is_refused(self):
        self.request_dir("1-1", request=self.req(), claim="  \n")
        (r,) = submit.scan(self.out).requests
        self.assertIsInstance(r, submit.Refused)
        self.assertIn("claim.md is empty", r.reason)

    def test_odd_names_are_shown_as_plain_text(self):
        (self.out / "submit").mkdir()
        name = "a\nb\udcff" + "x" * 300
        try:
            os.mkdir(os.path.join(str(self.out), "submit", name[:120]))
        except OSError:
            self.skipTest("this file system refuses the name")
        ((shown, _why),) = submit.scan(self.out).ignored
        shown.encode("ascii")                       # no exception
        self.assertLessEqual(len(shown), 80)
        import json
        json.dumps({"n": shown}, ensure_ascii=False).encode()

    def test_requests_that_cannot_be_answered_are_ignored_with_a_reason(self):
        self.request_dir("1-1", request="not json")
        self.request_dir("1-2", request="[1]")
        self.request_dir("1-3", request=self.req(request_id="short"))
        self.request_dir("1-4", request=None)
        self.request_dir("x-1", request=self.req())
        self.request_dir("0-1", request=self.req(0))
        self.request_dir("1000-1", request=self.req(1000))
        (self.out / "submit" / "1-5").write_text("a file, not a directory")
        s = submit.scan(self.out)
        self.assertEqual(s.requests, [])
        self.assertEqual(sorted(n for n, _ in s.ignored),
                         ["0-1", "1-1", "1-2", "1-3", "1-4", "1-5", "1000-1", "x-1"])

    def test_too_many_entries_is_a_problem_not_a_long_scan(self):
        (self.out / "submit").mkdir()
        for i in range(submit.MAX_ENTRIES + 1):
            (self.out / "submit" / f"junk{i}").mkdir()
        s = submit.scan(self.out)
        self.assertEqual(s.requests, [])
        self.assertIn("more than", s.problem)

    def test_order_does_not_read_file_times(self):
        # <k> first (slice-submit takes the lowest free one), then the slice
        # number. The owner sets file times; they decide nothing.
        for i, name in enumerate(("2-1", "1-2", "3-1", "1-1")):
            d = self.request_dir(name, request=self.req(int(name[0]), request_id=f"{i:032x}"))
            os.utime(d, ns=(10 ** 9 * (9 - i), 10 ** 9 * (9 - i)))
        self.assertEqual([r.dirname for r in submit.scan(self.out).requests],
                         ["1-1", "2-1", "3-1", "1-2"])


class TestInboxAndAnswer(Case):
    def test_a_request_is_handled_once_also_after_a_restart(self):
        run = state.RunDir("epic-902-test", base=self.tmp / "runs")
        run.create({"mode": "epic"})
        self.request_dir("1-1", request=self.req())
        self.request_dir("2-1", request=self.req(2, base="short", request_id="f" * 32))
        inbox = submit.Inbox(run)
        got = inbox.new(self.out).requests
        self.assertEqual([type(r) for r in got], [submit.Request, submit.Refused])
        inbox.mark(got[0], "accepted")
        self.assertEqual([r.dirname for r in inbox.new(self.out).requests], ["2-1"])
        inbox.mark(got[1], "refused")
        again = submit.Inbox(run)
        self.assertEqual(again.new(self.out).requests, [])
        # the same directory name with a new request id is a new request
        shutil.rmtree(self.out / "submit" / "1-1")
        self.request_dir("1-1", request=self.req(request_id="e" * 32))
        self.assertEqual([r.request_id for r in again.new(self.out).requests], ["e" * 32])

    def test_answer_file(self):
        a = submit.write_answer(self.ctx, 4, RID, accepted=True, round_no=2, files=10,
                                commit="c" * 40, parent="b" * 40)
        f = self.ctx / "slices" / "4" / "submitted.json"
        self.assertEqual(json.loads(f.read_text()), a)
        self.assertEqual(f.stat().st_mode & 0o777, 0o644)
        for slice_no, rid in ((0, RID), (True, RID), ("4", RID), (4, "../x"), (4, "")):
            with self.assertRaises(ValueError):
                submit.write_answer(self.ctx, slice_no, rid, accepted=True)

    def test_answer_is_not_written_through_a_link(self):
        d = self.ctx / "slices" / "5"
        d.mkdir(parents=True)
        os.symlink(self.secret, d / "submitted.json")
        submit.write_answer(self.ctx, 5, RID, accepted=False, reason="r")
        self.assertEqual(self.secret.read_text(), "HOST-SECRET-VALUE\n")
        self.assertFalse((d / "submitted.json").is_symlink())


if __name__ == "__main__":
    unittest.main(verbosity=2)
