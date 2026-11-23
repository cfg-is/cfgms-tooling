#!/usr/bin/env python3
"""
Tests: scripts/memory-sync.py, the host-side commit of the shared agent
memory folder. Every file in that folder is written by an agent and is
untrusted.

The two secret scanners are replaced by small programs on PATH, so the tests
need no gitleaks or truffleHog and no network. Git is real.

Run: python3 scripts/tests/test-memory-sync.py
"""
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SYNC_PATH = os.path.join(SCRIPT_DIR, "..", "memory-sync.py")

NOTE = "---\nauthor: owner/epic-7\n---\n\nA note.\n"


def _load():
    spec = importlib.util.spec_from_file_location("memory_sync", SYNC_PATH)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _git(*args, cwd):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.com",
                           "-c", "commit.gpgsign=false", *args],
                          cwd=cwd, check=True, capture_output=True).stdout.decode()


class MemorySync(unittest.TestCase):
    def setUp(self):
        self.ms = _load()
        self.root = Path(tempfile.mkdtemp(prefix="memsync-"))
        self.work = self.root / "memory"
        self.gitdir = self.root / "memory.git"
        self.state = self.root / "state"
        self.bin = self.root / "bin"
        self.work.mkdir()
        self.bin.mkdir()
        (self.work / "README.md").write_text("shared memory\n")
        _git("init", "-q", "-b", "main", cwd=self.work)
        _git("add", "README.md", cwd=self.work)
        _git("commit", "-q", "-m", "start", cwd=self.work)
        shutil.move(str(self.work / ".git"), str(self.gitdir))
        self.set_scanners()
        self.old_path = os.environ["PATH"]
        os.environ["PATH"] = "%s%s%s" % (self.bin, os.pathsep, self.old_path)
        self.repo = self.ms.Repo(str(self.gitdir), str(self.work), str(self.state))

    def tearDown(self):
        os.environ["PATH"] = self.old_path
        for here, dirs, files in os.walk(self.root):       # tests take permissions away
            for d in dirs:
                try:
                    os.chmod(os.path.join(here, d), 0o700, follow_symlinks=False)
                except (OSError, NotImplementedError):
                    pass
        shutil.rmtree(self.root, ignore_errors=True)

    def skip_if_root(self):
        """root reads a file whatever its mode: a test that takes the read
        right away proves nothing there. A visible skip, not a pass."""
        if os.geteuid() == 0:
            self.skipTest("runs as root: a file mode does not stop root from reading")

    def set_scanners(self, gitleaks="exit 0", trufflehog="exit 0"):
        for name, body in (("gitleaks", gitleaks), ("trufflehog", trufflehog)):
            p = self.bin / name
            p.write_text("#!/bin/sh\n%s\n" % body)
            p.chmod(0o755)

    def g(self, *args):
        return subprocess.run(["git", "--git-dir", str(self.gitdir), *args],
                              check=True, capture_output=True).stdout

    def head_files(self):
        return set(self.g("ls-tree", "-r", "--name-only", "-z", "HEAD").decode(
            errors="surrogateescape").strip("\0").split("\0"))

    def alerts(self):
        """Kind of each alert (a file holds one line for each alert)."""
        d = self.state / "alerts"
        return sorted(f.name.split("-", 1)[1][:-len(".json")]
                      for f in d.iterdir() for _ in f.read_text().splitlines())

    def note(self, rel, text=NOTE):
        p = self.work / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        return p

    def test_note_is_committed_with_its_author(self):
        self.note("areas/web/first.md")
        self.assertEqual(self.ms.cycle(self.repo, push=False), 1)
        self.assertIn("areas/web/first.md", self.head_files())
        self.assertEqual(self.g("log", "-1", "--format=%an|%cn|%s").decode().strip(),
                         "owner/epic-7|cfgms-memory-sync|memory: 1 file from owner/epic-7")
        self.assertEqual(self.ms.cycle(self.repo, push=False), 0)

    def test_commit_holds_the_checked_content_not_a_later_write(self):
        """The folder can change after the checks. The commit must hold the
        content that was checked."""
        p = self.note("areas/a.md")
        self.repo.git("add", "-A", "--", ":/")
        entries = [e for e in self.repo.staged() if e[3] == "areas/a.md"]
        self.assertEqual(len(entries), 1)
        p.write_text("changed after the checks: token=abc\n")
        self.ms.commit_checked(self.repo, "owner/epic-7", entries)
        self.assertEqual(self.g("show", "HEAD:areas/a.md").decode(), NOTE)

    def test_commit_does_not_take_a_symlink_swapped_in_after_the_checks(self):
        p = self.note("areas/a.md")
        self.repo.git("add", "-A", "--", ":/")
        entries = [e for e in self.repo.staged() if e[3] == "areas/a.md"]
        p.unlink()
        p.symlink_to("/etc/hostname")
        self.ms.commit_checked(self.repo, "owner/epic-7", entries)
        mode = self.g("ls-tree", "HEAD", "areas/a.md").decode().split()[0]
        self.assertEqual(mode, "100644")

    def test_note_replaced_by_a_folder_of_the_same_name(self):
        """A file / folder swap must not stop the cycle (it stopped every
        later cycle, and every other author's notes with it)."""
        self.note("areas/a.md")
        self.ms.cycle(self.repo, push=False)
        (self.work / "areas" / "a.md").unlink()
        self.note("areas/a.md/b.md", NOTE.replace("owner/epic-7", "alice"))
        self.note("areas/later.md", NOTE.replace("owner/epic-7", "zed"))
        self.ms.cycle(self.repo, push=False)
        self.assertEqual(self.head_files(), {"README.md", "areas/a.md/b.md", "areas/later.md"})
        self.assertEqual(self.ms.cycle(self.repo, push=False), 0)

    def test_folder_replaced_by_a_note_of_the_same_name(self):
        self.note("areas/x.md/y.md")
        self.ms.cycle(self.repo, push=False)
        shutil.rmtree(self.work / "areas" / "x.md")
        self.note("areas/x.md", NOTE.replace("owner/epic-7", "alice"))
        self.ms.cycle(self.repo, push=False)
        self.assertEqual(self.head_files(), {"README.md", "areas/x.md"})
        self.assertEqual(self.ms.cycle(self.repo, push=False), 0)

    def test_removed_note_is_removed_in_the_commit(self):
        p = self.note("areas/a.md")
        self.ms.cycle(self.repo, push=False)
        p.unlink()
        self.assertEqual(self.ms.cycle(self.repo, push=False), 1)
        self.assertEqual(self.head_files(), {"README.md"})

    def test_scanner_reads_the_committed_bytes_not_a_gitattributes_view(self):
        """A .gitattributes file in the folder is refused from the commit, and
        must not change the bytes that the scanners read."""
        (self.work / ".gitattributes").write_text("*.md working-tree-encoding=UTF-16LE\n")
        (self.work / "areas").mkdir()
        (self.work / "areas" / "n.md").write_bytes(NOTE.encode("utf-16-le"))
        seen = self.root / "seen"
        self.set_scanners(gitleaks='''
src=""
while [ $# -gt 0 ]; do
  case "$1" in --source) src="$2"; shift ;; esac
  shift
done
cp "${src}areas/n.md" "%s"
exit 0''' % seen)
        self.ms.cycle(self.repo, push=False)
        self.assertEqual(seen.read_bytes(), self.g("cat-file", "blob", "HEAD:areas/n.md"))

    def test_file_outside_the_allow_list_is_refused(self):
        self.note("areas/ok.md")
        self.note("notes.txt", "x\n")
        self.note("areas/run.sh", "#!/bin/sh\n")
        self.ms.cycle(self.repo, push=False)
        self.assertEqual(self.head_files(), {"README.md", "areas/ok.md"})
        self.assertEqual(self.alerts(), ["refused_path_not_allowed"] * 2)

    def test_name_that_ends_in_a_newline_is_refused(self):
        self.assertIsNone(self.ms.refuse_reason("A", "100644", "areas/x.md"))
        self.assertEqual(self.ms.refuse_reason("A", "100644", "areas/x.md\n"), "path_not_allowed")

    def test_symlink_and_executable_are_refused(self):
        (self.work / "areas").mkdir()
        (self.work / "areas" / "link.md").symlink_to("/etc/hostname")
        exe = self.note("areas/exe.md")
        exe.chmod(exe.stat().st_mode | stat.S_IXUSR)
        self.ms.cycle(self.repo, push=False)
        self.assertEqual(self.head_files(), {"README.md"})

    def test_name_that_is_not_utf8_does_not_stop_the_cycle(self):
        self.note("areas/ok.md")
        with open(os.path.join(os.fsencode(str(self.work)), b"bad\xff.txt"), "wb") as f:
            f.write(b"x\n")
        self.assertEqual(self.ms.cycle(self.repo, push=False), 1)
        self.assertEqual(self.head_files(), {"README.md", "areas/ok.md"})
        self.assertTrue((self.state / "refused.json").is_file())
        # the second cycle must work too, and must not alert again
        before = self.alerts()
        self.assertEqual(self.ms.cycle(self.repo, push=False), 0)
        self.assertEqual(self.alerts(), before)

    def test_secret_hit_moves_the_file_to_quarantine(self):
        self.note("areas/ok.md")
        self.note("areas/leak.md")
        self.set_scanners(gitleaks='''
src=""; rep=""
while [ $# -gt 0 ]; do
  case "$1" in --source) src="$2"; shift ;; --report-path) rep="$2"; shift ;; esac
  shift
done
printf '[{"File": "%sareas/leak.md"}]' "$src" > "$rep"
exit 9''')
        self.assertEqual(self.ms.cycle(self.repo, push=False), 1)
        self.assertEqual(self.head_files(), {"README.md", "areas/ok.md"})
        self.assertFalse((self.work / "areas" / "leak.md").exists())
        self.assertEqual(len(list((self.state / "quarantine").iterdir())), 1)

    def test_secret_hit_on_an_unknown_path_commits_nothing(self):
        self.note("areas/ok.md")
        self.set_scanners(gitleaks='''
rep=""
while [ $# -gt 0 ]; do
  case "$1" in --report-path) rep="$2"; shift ;; esac
  shift
done
printf '[{"File": "/somewhere/else.md"}]' > "$rep"
exit 9''')
        with self.assertRaises(RuntimeError):
            self.ms.cycle(self.repo, push=False)
        self.assertEqual(self.head_files(), {"README.md"})

    def test_missing_scanner_commits_nothing(self):
        self.note("areas/ok.md")
        real = shutil.which
        with mock.patch.object(self.ms.shutil, "which",
                               lambda tool: None if tool == "trufflehog" else real(tool)):
            with self.assertRaises(RuntimeError):
                self.ms.cycle(self.repo, push=False)
        self.assertEqual(self.head_files(), {"README.md"})

    def test_long_path_can_be_quarantined(self):
        rel = "areas/" + "/".join(["d" * 60] * 5) + "/n.md"
        self.note(rel)
        self.repo.quarantine_file(rel, "secret_test")
        self.assertFalse((self.work / rel).exists())
        self.assertEqual(len(list((self.state / "quarantine").iterdir())), 1)

    def test_git_dir_inside_the_folder_is_refused(self):
        r = subprocess.run(["python3", SYNC_PATH, "once", "--git-dir", str(self.work / "x.git"),
                            "--work-tree", str(self.work), "--state-dir", str(self.state), "--no-push"],
                           capture_output=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn(b"inside the mounted folder", r.stderr)

    # --- a `.git` entry in the folder ---------------------------------------------
    # An agent can put a `.git` entry (a directory, a file or a link) in any
    # folder. Before, its whole folder was left out: one owner stopped the save
    # of the notes of the others. Now the entry is moved into the quarantine
    # (one rename; never followed, never read by git) and everything is saved.

    def quarantined(self):
        return sorted(p.name for p in (self.state / "quarantine").iterdir() if p.name.startswith("git-"))

    def git_entry_cycle(self, rel):
        """One cycle with a `.git` entry in `rel`, a note in `rel` and a note
        of another owner beside it: both notes are committed in that call."""
        (self.work / rel).mkdir(parents=True, exist_ok=True)
        (self.work / rel / "inside.md").write_text(NOTE)
        self.note("areas/beside.md", NOTE.replace("owner/epic-7", "owner/epic-8"))
        self.assertEqual(self.ms.cycle(self.repo, push=False), 2)
        files = self.head_files()
        self.assertIn("areas/beside.md", files)
        self.assertIn(rel + "/inside.md", files)
        self.assertEqual([f for f in files if ".git" in f.split("/")], [])
        self.assertEqual(self.alerts(), ["git_entry_quarantined"])
        self.assertFalse(os.path.lexists(self.work / rel / ".git"))
        self.assertEqual(len(self.quarantined()), 1)
        self.assertEqual(self.repo.result, {"committed": 2, "alerts": 1, "refused": 0, "pending": 0, "pending_calls": 0})
        self.assertEqual(self.g("ls-tree", "HEAD", "--", rel + "/inside.md")[:6], b"100644")   # a note, no link
        self.assertEqual(self.ms.cycle(self.repo, push=False), 0)
        self.assertEqual(self.repo.result, {"committed": 0, "alerts": 0, "refused": 0, "pending": 0, "pending_calls": 0})

    def test_a_git_file_beside_notes_does_not_hold_them_back(self):
        """`touch areas/.git` and a note of another owner in areas/: the note
        is saved in the same call."""
        (self.work / "areas").mkdir()
        (self.work / "areas" / ".git").write_text("gitdir: /nowhere\n")
        self.note("areas/other-owner.md", NOTE.replace("owner/epic-7", "owner/epic-9"))
        self.assertEqual(self.ms.cycle(self.repo, push=False), 1)
        self.assertIn("areas/other-owner.md", self.head_files())
        self.assertEqual(self.alerts(), ["git_entry_quarantined"])

    def test_nested_repository_with_no_commit_is_quarantined(self):
        (self.work / "areas" / "sub").mkdir(parents=True)
        _git("init", "-q", cwd=self.work / "areas" / "sub")
        self.git_entry_cycle("areas/sub")

    def test_nested_repository_with_a_commit_is_quarantined(self):
        (self.work / "areas" / "sub").mkdir(parents=True)
        _git("init", "-q", cwd=self.work / "areas" / "sub")
        _git("commit", "-q", "--allow-empty", "-m", "x", cwd=self.work / "areas" / "sub")
        self.git_entry_cycle("areas/sub")

    def test_nested_git_file_is_quarantined(self):
        (self.work / "areas" / "sub").mkdir(parents=True)
        (self.work / "areas" / "sub" / ".git").write_text("gitdir: /nowhere\n")
        self.git_entry_cycle("areas/sub")

    def test_nested_git_link_is_moved_as_a_link_and_not_followed(self):
        target = self.root / "target"
        target.mkdir()
        (target / "keep").write_text("host file\n")
        (self.work / "areas" / "sub").mkdir(parents=True)
        os.symlink(target, self.work / "areas" / "sub" / ".git")
        self.git_entry_cycle("areas/sub")
        moved = self.state / "quarantine" / self.quarantined()[0]
        self.assertTrue(moved.is_symlink())
        self.assertEqual((target / "keep").read_text(), "host file\n")    # the target is not touched

    def test_a_link_to_a_folder_is_not_walked(self):
        outside = self.root / "outside"
        (outside / "deep" / ".git").mkdir(parents=True)
        (self.work / "areas").mkdir()
        os.symlink(outside, self.work / "areas" / "link")
        self.note("areas/beside.md")
        self.ms.cycle(self.repo, push=False)
        self.assertTrue((outside / "deep" / ".git").is_dir())             # not moved
        self.assertEqual(self.quarantined(), [])

    def test_git_entry_at_the_top_is_quarantined(self):
        (self.work / ".git" / "hooks").mkdir(parents=True)
        self.note("areas/beside.md")
        self.assertEqual(self.ms.cycle(self.repo, push=False), 1)
        self.assertFalse(os.path.lexists(self.work / ".git"))
        self.assertEqual(self.alerts(), ["git_entry_quarantined"])
        self.assertEqual([f for f in self.head_files() if ".git" in f], [])

    def test_a_folder_with_a_pattern_name_that_is_left_out_leaves_out_only_itself(self):
        """A folder named `*` whose `.git` cannot be moved: as a pattern it
        would leave out every note in `areas/`. The name is taken as it is
        written."""
        (self.work / "areas" / "*").mkdir(parents=True)
        (self.work / "areas" / "*" / ".git").write_text("x")
        self.note("areas/beside.md")
        real = os.rename

        def rename(src, dst, *a, **kw):
            if src == ".git":
                raise OSError(18, "Invalid cross-device link")
            return real(src, dst, *a, **kw)
        with mock.patch.object(self.ms.os, "rename", rename):
            self.assertEqual(self.ms.cycle(self.repo, push=False), 1)
        self.assertIn("areas/beside.md", self.head_files())

    def test_a_git_entry_that_cannot_be_moved_is_held_and_nothing_below_is_removed(self):
        """A rename that fails (for example to another file system) copies
        nothing: the entry stays, every call counts it in `refused`, one
        alert. git never reads the folder, so the notes beside it are saved;
        a note of that folder that is gone is not removed while the entry
        is there."""
        self.note("areas/sub/kept.md")
        self.assertEqual(self.ms.cycle(self.repo, push=False), 1)
        (self.work / "areas" / "sub" / "kept.md").unlink()
        (self.work / "areas" / "sub" / ".git").write_text("x")
        (self.work / "areas" / "sub" / "inside.md").write_text(NOTE)
        self.note("areas/beside.md")
        real = os.rename

        def rename(src, dst, *a, **kw):
            if src == ".git":
                raise OSError(18, "Invalid cross-device link")
            return real(src, dst, *a, **kw)
        with mock.patch.object(self.ms.os, "rename", rename):
            self.assertEqual(self.ms.cycle(self.repo, push=False), 1)
            self.assertEqual(self.repo.result["refused"], 1)
            self.assertEqual(self.alerts(), ["refused_git_entry_not_movable"])
            self.assertEqual(self.ms.cycle(self.repo, push=False), 0)
            self.assertEqual(self.repo.result, {"committed": 0, "alerts": 0, "refused": 1, "pending": 0, "pending_calls": 0})
        files = self.head_files()
        self.assertIn("areas/beside.md", files)
        self.assertIn("areas/sub/inside.md", files)
        self.assertIn("areas/sub/kept.md", files)                         # not removed
        self.assertTrue((self.work / "areas" / "sub" / ".git").exists())
        self.assertEqual(self.quarantined(), [])

    def test_a_note_that_was_committed_stays_when_its_folder_gets_a_git_entry(self):
        self.note("areas/sub/kept.md")
        self.assertEqual(self.ms.cycle(self.repo, push=False), 1)
        _git("init", "-q", cwd=self.work / "areas" / "sub")
        self.assertEqual(self.ms.cycle(self.repo, push=False), 0)
        self.assertIn("areas/sub/kept.md", self.head_files())

    # --- entries that `git add` cannot read ---------------------------------------
    # None of them may stop the save of the rest. Each is left out, alerted one
    # time, and counted in `refused` on every call while it is there.

    def held_cycle(self, kind, *, alert=None):
        self.note("areas/beside.md")
        self.assertEqual(self.ms.cycle(self.repo, push=False), 1)
        self.assertIn("areas/beside.md", self.head_files())
        self.assertEqual(self.alerts(), [alert or "refused_" + kind])
        self.assertEqual(self.repo.result["refused"], 1)
        self.assertEqual(self.ms.cycle(self.repo, push=False), 0)
        self.assertEqual(self.repo.result, {"committed": 0, "alerts": 0, "refused": 1, "pending": 0, "pending_calls": 0})

    def test_an_unreadable_file_is_left_out(self):
        self.skip_if_root()
        p = self.note("areas/locked.md")
        p.chmod(0)
        self.held_cycle("unreadable_file")
        self.assertNotIn("areas/locked.md", self.head_files())

    def test_a_fifo_is_left_out(self):
        (self.work / "areas").mkdir()
        os.mkfifo(self.work / "areas" / "pipe.md")
        self.held_cycle("special_file")

    def test_a_socket_is_left_out(self):
        import socket
        (self.work / "areas").mkdir()
        old = os.getcwd()
        os.chdir(self.work / "areas")                  # a short path: socket paths are short
        s = socket.socket(socket.AF_UNIX)
        try:
            s.bind("sock.md")
        finally:
            os.chdir(old)
        try:
            self.held_cycle("special_file")
        finally:
            s.close()

    def test_a_device_is_left_out(self):
        """A device node needs root to make: the walk is given one by its
        lstat answer."""
        self.note("areas/dev.md")
        real = os.stat

        def fake_stat(name, *a, **kw):
            st = real(name, *a, **kw)
            if name == "dev.md":
                return os.stat_result((stat.S_IFCHR | 0o644,) + tuple(st)[1:])
            return st
        with mock.patch.object(self.ms.os, "stat", fake_stat):
            walk = self.ms.walk_tree(self.repo, {}, {})
        self.assertEqual(walk["held"], [("special_file", "areas/dev.md")])
        self.assertIn("areas/dev.md", walk["present"])

    def test_a_dangling_link_is_refused_and_the_rest_saved(self):
        (self.work / "areas").mkdir()
        os.symlink(self.root / "nowhere", self.work / "areas" / "dangling.md")
        self.held_cycle("not_a_plain_file", alert="refused_not_a_plain_file")

    def test_folders_that_cannot_be_read_or_entered_are_left_out(self):
        self.skip_if_root()
        for name, mode in (("closed", 0), ("no-enter", 0o644), ("no-list", 0o311)):
            with self.subTest(name=name):
                self.tearDown()
                self.setUp()
                self.note("areas/%s/kept.md" % name)
                self.assertEqual(self.ms.cycle(self.repo, push=False), 1)       # committed before
                self.note("areas/%s/new.md" % name)
                (self.work / "areas" / name).chmod(mode)
                self.held_cycle("unreadable_dir")
                files = self.head_files()
                self.assertIn("areas/%s/kept.md" % name, files)                 # not taken as removed
                self.assertNotIn("areas/%s/new.md" % name, files)

    # --- git does not read the folder: the host reads each note itself -------------

    def set_hook(self, fn):
        self.ms._before_read = fn
        self.addCleanup(setattr, self.ms, "_before_read", None)

    def test_a_very_deep_folder_does_not_stop_the_save(self):
        (self.work / "areas").mkdir()
        fds = [os.open(str(self.work / "areas"), os.O_RDONLY | os.O_DIRECTORY)]
        for _ in range(1000):                       # 1000 levels, made without recursion
            os.mkdir("d", dir_fd=fds[-1])
            fds.append(os.open("d", os.O_RDONLY | os.O_DIRECTORY, dir_fd=fds[-1]))

        def remove_deep():
            for parent in reversed(fds[:-1]):
                os.rmdir("d", dir_fd=parent)
            for fd in fds:
                os.close(fd)
        try:                                        # removed before tearDown's rmtree
            self.note("areas/beside.md")
            self.assertEqual(self.ms.cycle(self.repo, push=False), 1)
            self.assertIn("areas/beside.md", self.head_files())
            self.assertEqual(self.alerts(), ["refused_too_deep"])
            self.assertEqual(self.repo.result["refused"], 1)
        finally:
            remove_deep()

    def test_a_file_made_unreadable_between_the_walk_and_the_read(self):
        """The review's chmod race, made certain by the hook."""
        self.skip_if_root()
        kept = self.note("areas/kept.md")
        self.ms.cycle(self.repo, push=False)
        kept.write_text(NOTE + "changed\n")
        self.note("areas/other.md", NOTE.replace("owner/epic-7", "owner/epic-8"))
        self.set_hook(lambda p: os.chmod(self.work / p, 0) if p == "areas/kept.md" else None)
        self.assertEqual(self.ms.cycle(self.repo, push=False), 1)
        files = self.head_files()
        self.assertIn("areas/other.md", files)
        self.assertIn("areas/kept.md", files)                            # held, not removed
        self.assertEqual(self.g("show", "HEAD:areas/kept.md").decode(), NOTE)
        self.assertIn("refused_unreadable_file", self.alerts())

    def test_a_fifo_or_a_link_swapped_in_before_the_read_is_held(self):
        for kind in ("fifo", "link"):
            with self.subTest(kind=kind):
                self.tearDown()
                self.setUp()
                self.note("areas/swap.md")
                self.note("areas/other.md")

                def swap(p, kind=kind):
                    if p == "areas/swap.md":
                        os.unlink(self.work / p)
                        if kind == "fifo":
                            os.mkfifo(self.work / p)
                        else:
                            os.symlink("/etc/hostname", self.work / p)
                self.set_hook(swap)
                self.assertEqual(self.ms.cycle(self.repo, push=False), 1)      # no hang, no stop
                self.assertEqual(sorted(self.head_files()), ["README.md", "areas/other.md"])
                self.assertEqual(self.alerts(), ["refused_read_failed"])

    def test_a_file_that_grows_past_the_limit_before_the_read(self):
        self.note("areas/grow.md")
        self.note("areas/other.md")
        self.set_hook(lambda p: (self.work / p).write_bytes(b"x" * (self.ms.MAX_FILE_BYTES + 10))
                      if p == "areas/grow.md" else None)
        self.assertEqual(self.ms.cycle(self.repo, push=False), 1)
        self.assertNotIn("areas/grow.md", self.head_files())
        self.assertEqual(self.alerts(), ["refused_too_large"])

    def test_a_file_that_vanishes_before_the_read_is_not_removed_in_that_call(self):
        p = self.note("areas/gone.md")
        self.ms.cycle(self.repo, push=False)
        p.write_text(NOTE + "changed\n")
        self.set_hook(lambda q: os.unlink(self.work / q) if q == "areas/gone.md" else None)
        self.assertEqual(self.ms.cycle(self.repo, push=False), 0)
        self.assertIn("areas/gone.md", self.head_files())
        self.assertEqual(self.alerts(), ["refused_read_failed"])
        self.set_hook(None)
        self.assertEqual(self.ms.cycle(self.repo, push=False), 1)        # now it is a removal
        self.assertNotIn("areas/gone.md", self.head_files())

    def test_a_huge_sparse_file_is_refused_without_a_read(self):
        self.note("areas/other.md")
        with open(self.work / "areas" / "huge.md", "wb") as fh:
            fh.truncate(20 * 1024 ** 3)                                   # 20 GB, sparse
        t0 = time.time()
        self.assertEqual(self.ms.cycle(self.repo, push=False), 1)
        self.assertLess(time.time() - t0, 10)
        self.assertEqual(sorted(self.head_files()), ["README.md", "areas/other.md"])
        self.assertEqual(self.alerts(), ["refused_too_large"])

    def test_a_walk_that_reaches_the_entry_limit_removes_nothing(self):
        for i in range(3):
            self.note("areas/n%d.md" % i)
        self.ms.cycle(self.repo, push=False)
        for i in range(3):
            os.unlink(self.work / "areas" / ("n%d.md" % i))
        for i in range(10):
            self.note("areas/z%d.md" % i)
        saved = self.ms.MAX_ENTRIES
        self.ms.MAX_ENTRIES = 5
        self.addCleanup(setattr, self.ms, "MAX_ENTRIES", saved)
        self.ms.cycle(self.repo, push=False)
        files = self.head_files()
        self.assertTrue({"areas/n0.md", "areas/n1.md", "areas/n2.md"} <= files)   # nothing removed
        self.assertIn("refused_too_many_entries", self.alerts())

    def test_the_first_call_with_no_cache_removes_nothing_that_cannot_be_read(self):
        """The first sync after notes-setup: no cache, a tracked note and a
        tracked folder that cannot be read are held, not removed."""
        self.skip_if_root()
        self.note("areas/a.md")
        self.note("areas/d/b.md")
        self.ms.cycle(self.repo, push=False)
        shutil.rmtree(self.state)                                         # a new host state
        self.repo = self.ms.Repo(str(self.gitdir), str(self.work), str(self.state))
        (self.work / "areas" / "a.md").chmod(0)
        (self.work / "areas" / "d").chmod(0)
        self.assertEqual(self.ms.cycle(self.repo, push=False), 0)
        self.assertTrue({"areas/a.md", "areas/d/b.md"} <= self.head_files())
        self.assertEqual(self.repo.result["refused"], 2)

    def test_the_quarantine_keeps_a_bounded_number_and_size(self):
        q = self.state / "quarantine"
        q.mkdir(parents=True, exist_ok=True)
        for i in range(self.ms.QUARANTINE_MAX_ENTRIES + 10):
            (q / ("git-2026010%02d-x" % i)).mkdir()
        (q / "20260101-secret-kept").write_text("x")                      # a secret file: not touched
        self.ms.prune_quarantine(str(q))
        names = sorted(p.name for p in q.iterdir() if p.name.startswith("git-"))
        self.assertEqual(len(names), self.ms.QUARANTINE_MAX_ENTRIES)
        self.assertEqual(names[0], "git-202601010-x")                     # the oldest 10 are gone
        self.assertTrue((q / "20260101-secret-kept").exists())
        big = q / "git-29990101-big"
        big.mkdir()
        with open(big / "f", "wb") as fh:
            fh.truncate(self.ms.QUARANTINE_MAX_BYTES + 1)
        self.ms.prune_quarantine(str(q))
        self.assertFalse(big.exists())                                    # alone over the size

    # --- fairness and a streak of calls with notes that wait ----------------------

    def test_one_owner_with_many_changes_does_not_hold_back_the_others(self):
        """The review's case: an owner rewrites many notes in areas/-/ each
        call; the notes of the others are saved on the first call."""
        self.small_batch(5)
        for i in range(20):
            self.note("areas/-/f%02d.md" % i, NOTE.replace("owner/epic-7", "spam"))
        self.note("areas/zz-other.md", NOTE.replace("owner/epic-7", "other"))
        self.note("held/q.md", NOTE.replace("owner/epic-7", "held"))
        self.ms.cycle(self.repo, push=False)
        files = self.head_files()
        self.assertIn("areas/zz-other.md", files)
        self.assertIn("held/q.md", files)
        self.assertEqual(self.repo.result["pending"], 17)

    def test_a_group_that_keeps_changing_goes_on_after_its_cursor(self):
        """An owner rewrites the same 4 notes before each call: with a batch
        of 2, the next call takes the next 2, not the first 2 again."""
        self.small_batch(2)
        names = ["areas/-/f%d.md" % i for i in range(4)]
        for rnd in range(2):
            for n in names:
                self.note(n, NOTE + "round %d\n" % rnd)
            self.ms.cycle(self.repo, push=False)
        got = {n: self.g("show", "HEAD:" + n).decode().endswith("round 1\n") for n in names}
        self.assertEqual(got, {names[0]: False, names[1]: False, names[2]: True, names[3]: True})

    def test_a_note_that_did_not_change_is_not_read_again(self):
        for i in range(3):
            self.note("areas/c%d.md" % i)
        reads = []
        self.set_hook(reads.append)
        self.ms.cycle(self.repo, push=False)
        self.assertEqual(sorted(reads), ["README.md", "areas/c0.md", "areas/c1.md", "areas/c2.md"])
        reads.clear()
        self.ms.cycle(self.repo, push=False)
        self.assertEqual(reads, [])                                       # the cache: no read
        self.note("areas/c1.md", NOTE + "changed\n")
        self.ms.cycle(self.repo, push=False)
        self.assertEqual(reads, ["areas/c1.md"])

    def test_a_cycle_keeps_the_quarantine_bounded(self):
        q = self.state / "quarantine"
        for i in range(self.ms.QUARANTINE_MAX_ENTRIES + 5):
            (q / ("git-2020010%02d-x" % i)).mkdir()
        (self.work / ".git").mkdir()
        self.ms.cycle(self.repo, push=False)
        self.assertEqual(len([p for p in q.iterdir() if p.name.startswith("git-")]),
                         self.ms.QUARANTINE_MAX_ENTRIES)

    def test_three_calls_in_a_row_with_notes_that_wait(self):
        self.small_batch(1)
        for i in range(4):
            self.note("areas/s/%d.md" % i)
        calls = []
        for _ in range(4):
            self.ms.cycle(self.repo, push=False)
            calls.append((self.repo.result["pending"], self.repo.result["pending_calls"]))
        self.assertEqual(calls, [(3, 1), (2, 2), (1, 3), (0, 0)])         # reset when nothing waits

    # --- a bounded batch ----------------------------------------------------------

    def small_batch(self, n):
        saved = self.ms.BATCH_SIZE
        self.ms.BATCH_SIZE = n
        self.addCleanup(setattr, self.ms, "BATCH_SIZE", saved)

    def test_more_changes_than_the_batch_are_saved_over_two_calls(self):
        self.small_batch(3)
        for i in range(5):
            self.note("areas/b/n%d.md" % i, NOTE.replace("owner/epic-7", "owner/epic-%d" % (i % 2)))
        self.assertEqual(self.ms.cycle(self.repo, push=False), 2)          # two authors: two commits
        self.assertEqual(self.repo.result["pending"], 2)
        self.assertEqual(sorted(f for f in self.head_files() if f.startswith("areas/b/")),
                         ["areas/b/n0.md", "areas/b/n1.md", "areas/b/n2.md"])   # the first 3 by path
        self.assertEqual(self.ms.cycle(self.repo, push=False), 2)
        self.assertEqual(self.repo.result["pending"], 0)
        self.assertEqual(len([f for f in self.head_files() if f.startswith("areas/b/")]), 5)
        self.assertEqual(self.ms.cycle(self.repo, push=False), 0)

    def test_refused_files_take_no_place_in_the_batch(self):
        self.small_batch(2)
        for i in range(4):
            (self.work / ("a%d.sh" % i)).write_text("x")                  # sorts before areas/
        self.note("areas/x.md")
        self.note("areas/y.md")
        self.assertEqual(self.ms.cycle(self.repo, push=False), 1)
        self.assertEqual(self.repo.result["pending"], 0)
        self.assertIn("areas/y.md", self.head_files())
        self.assertEqual(self.repo.result["refused"], 4)

    def test_removals_and_adds_in_one_update_index(self):
        """Many removals and adds go into one commit (one update-index)."""
        for i in range(4):
            self.note("areas/r.md/%d.md" % i)
        self.assertEqual(self.ms.cycle(self.repo, push=False), 1)
        shutil.rmtree(self.work / "areas" / "r.md")
        self.note("areas/r.md", NOTE)                                      # a note where the folder was
        self.assertEqual(self.ms.cycle(self.repo, push=False), 2)          # the removals, then the add
        files = self.head_files()
        self.assertIn("areas/r.md", files)
        self.assertEqual([f for f in files if f.startswith("areas/r.md/")], [])

    # --- what a caller reads ------------------------------------------------------

    def run_once(self, *extra):
        return subprocess.run(["python3", SYNC_PATH, "once", "--git-dir", str(self.gitdir),
                               "--work-tree", str(self.work), "--state-dir", str(self.state),
                               "--no-push", *extra], capture_output=True)

    def test_the_result_file_counts_this_call(self):
        result = self.root / "result.json"
        self.note("areas/a.md")
        (self.work / "areas" / "run.sh").write_text("x")
        r = self.run_once("--result-file", str(result))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(result.read_text()), {"committed": 1, "alerts": 1, "refused": 1, "pending": 0, "pending_calls": 0})
        r = self.run_once("--result-file", str(result))
        self.assertEqual(json.loads(result.read_text()), {"committed": 0, "alerts": 0, "refused": 1, "pending": 0, "pending_calls": 0})

    def test_a_name_with_a_newline_makes_one_log_line(self):
        (self.work / "areas").mkdir()
        (self.work / "areas" / "x\n2026 ALERT fake: y.sh").write_text("x")
        r = self.run_once()
        self.assertEqual(r.returncode, 0, r.stderr)
        lines = r.stdout.decode().splitlines()
        self.assertEqual(len([l for l in lines if " ALERT " in l]), 1)
        self.assertIn("\\x0a", r.stdout.decode())

    def test_a_held_lock_exits_75(self):
        import fcntl
        self.state.mkdir(exist_ok=True)
        with open(self.state / "lock", "w") as fh:
            fcntl.flock(fh, fcntl.LOCK_EX)
            r = self.run_once()
        self.assertEqual(r.returncode, 75)

    def quarantine_top(self, git_dir=None):
        r = subprocess.run(["python3", SYNC_PATH, "quarantine-top-git", "--git-dir",
                            str(git_dir or self.gitdir), "--work-tree", str(self.work),
                            "--state-dir", str(self.state)], capture_output=True)
        return r.returncode, r.stdout.decode().strip()

    def test_quarantine_top_git(self):
        self.skip_if_root()
        self.assertEqual(self.quarantine_top(), (0, "NONE"))
        (self.work / ".git").write_text("gitdir: /x\n")
        rc, line = self.quarantine_top()
        self.assertEqual(rc, 0)
        self.assertTrue(line.startswith("MOVED:" + str(self.state / "quarantine" / "git-")), line)
        self.assertFalse(os.path.lexists(self.work / ".git"))
        os.symlink(self.root / "nowhere", self.work / ".git")
        self.assertEqual(self.quarantine_top(self.root / "no-git-dir"), (3, "NO_GIT_DIR"))
        self.assertTrue(os.path.lexists(self.work / ".git"))
        self.assertEqual(self.quarantine_top(self.work / ".git"), (3, "NO_GIT_DIR"))   # in the folder
        (self.state / "quarantine").chmod(0o500)
        try:
            rc, line = self.quarantine_top()
        finally:
            (self.state / "quarantine").chmod(0o700)
        self.assertEqual(rc, 4)
        self.assertTrue(line.startswith("NOT_MOVABLE:"), line)
        self.assertTrue(os.path.lexists(self.work / ".git"))

    def test_a_stopped_cycle_leaves_nothing_for_the_next_start(self):
        """A cycle that was killed leaves its scan folder (copies of notes)
        and its private index. The next start removes them."""
        self.state.mkdir(exist_ok=True)
        (self.state / "scan-old" / "tree").mkdir(parents=True)
        (self.state / "scan-old" / "tree" / "n.md").write_text(NOTE)
        (self.state / "index-old").write_text("x")
        (self.state / "refused.json").write_text("[]")
        r = subprocess.run(["python3", SYNC_PATH, "once", "--git-dir", str(self.gitdir),
                            "--work-tree", str(self.work), "--state-dir", str(self.state), "--no-push"],
                           capture_output=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(sorted(p.name for p in self.state.iterdir()
                                if p.name.startswith(("scan-", "index-"))), [])
        self.assertTrue((self.state / "refused.json").exists())

    def test_detach_help_says_when_it_may_be_used(self):
        r = subprocess.run(["python3", SYNC_PATH, "--help"], capture_output=True)
        self.assertIn(b"no container ever", b" ".join(r.stdout.split()))


if __name__ == "__main__":
    unittest.main()
