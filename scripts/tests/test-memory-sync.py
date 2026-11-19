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
import os
import shutil
import stat
import subprocess
import tempfile
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
        shutil.rmtree(self.root, ignore_errors=True)

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


if __name__ == "__main__":
    unittest.main()
