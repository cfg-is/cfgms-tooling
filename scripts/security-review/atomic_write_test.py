#!/usr/bin/env python3
"""Coverage tests for atomic_write.py.

Run: python3 .claude/scripts/security-review/atomic_write_test.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import atomic_write  # noqa: E402

FAILURES: list[str] = []


def check(cond: bool, name: str, detail: str = "") -> None:
    if cond:
        print(f"  [PASS] {name}")
    else:
        FAILURES.append(name)
        print(f"  [FAIL] {name}" + (f"\n         {detail}" if detail else ""))


def test_write_then_read_round_trips():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "step-001.findings.json")
        data = {"sweep_id": "abc", "findings": [1, 2, 3]}
        atomic_write.write_json_atomic(path, data)
        with open(path) as f:
            got = json.load(f)
        check(got == data, "write_json_atomic: round trips through JSON", str(got))


def test_no_tmp_file_left_behind_on_success():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "step-001.findings.json")
        atomic_write.write_json_atomic(path, {"a": 1})
        check(
            not os.path.exists(path + ".tmp"),
            "write_json_atomic: no .tmp sibling left after a successful write",
        )


def test_interrupted_write_leaves_no_file_when_none_existed():
    # REQUIRED TEST: a write interrupted after the .tmp file is partially
    # flushed must never leave a truncated file visible at the final path.
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "step-002.findings.json")

        def partial_then_raise(obj, fp, **kwargs):
            fp.write('{"partial": true, "incomplete')  # no closing brace/quote
            fp.flush()
            raise RuntimeError("simulated crash mid-write")

        with mock.patch.object(atomic_write.json, "dump", side_effect=partial_then_raise):
            raised = False
            try:
                atomic_write.write_json_atomic(path, {"anything": 1})
            except RuntimeError:
                raised = True
        check(raised, "write_json_atomic: propagates the underlying write failure")
        check(
            not os.path.exists(path),
            "write_json_atomic: interrupted write with no prior file leaves nothing at final path",
        )


def test_interrupted_write_preserves_previous_complete_version():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "step-003.findings.json")
        atomic_write.write_json_atomic(path, {"version": "good"})

        def partial_then_raise(obj, fp, **kwargs):
            fp.write('{"version": "cor')  # truncated
            fp.flush()
            raise RuntimeError("simulated crash mid-write")

        with mock.patch.object(atomic_write.json, "dump", side_effect=partial_then_raise):
            try:
                atomic_write.write_json_atomic(path, {"version": "bad"})
            except RuntimeError:
                pass

        with open(path) as f:
            got = json.load(f)
        check(
            got == {"version": "good"},
            "write_json_atomic: an interrupted overwrite never truncates the previous complete file",
            str(got),
        )


def test_atomic_rename_used_not_plain_rename():
    # os.replace (not os.rename) is required: unlike os.rename on Windows,
    # os.replace succeeds even when the destination already exists.
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "step-004.findings.json")
        atomic_write.write_json_atomic(path, {"v": 1})
        # Second write to the same (already-existing) path must not raise.
        try:
            atomic_write.write_json_atomic(path, {"v": 2})
            ok = True
        except OSError:
            ok = False
        check(ok, "write_json_atomic: overwriting an existing final path succeeds (os.replace semantics)")
        with open(path) as f:
            got = json.load(f)
        check(got == {"v": 2}, "write_json_atomic: overwrite is reflected at the final path", str(got))


def test_write_json_atomic_does_not_touch_a_planted_fixed_tmp_symlink():
    # REQUIRED TEST: the old implementation opened a predictable `<path>.tmp`
    # name. A container (or any other process sharing this directory) able to
    # pre-plant a symlink at that guessable name would have the host process
    # follow it, truncating and rewriting whatever file the symlink points at.
    # The mkstemp-based implementation never even looks at that fixed name, so
    # a planted symlink there is simply inert.
    with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
        path = os.path.join(tmp, "step-005.findings.json")
        victim = os.path.join(outside, "victim.txt")
        with open(victim, "w") as f:
            f.write("original host content\n")
        os.symlink(victim, f"{path}.tmp")

        atomic_write.write_json_atomic(path, {"a": 1})

        with open(victim) as f:
            victim_content = f.read()
        check(
            victim_content == "original host content\n",
            "write_json_atomic: a symlink planted at the fixed <path>.tmp name is never followed or touched",
            victim_content,
        )
        with open(path) as f:
            got = json.load(f)
        check(got == {"a": 1}, "write_json_atomic: the real write still succeeds despite the planted symlink", str(got))
        check(os.path.isfile(path) and not os.path.islink(path), "write_json_atomic: the final path is a real file, not the planted link")


def test_write_json_atomic_temp_file_created_via_mkstemp_in_dest_dir():
    # REQUIRED TEST: the temp file must be created with tempfile.mkstemp in the
    # destination directory, not a fixed <path>.tmp name -- matching the
    # pattern already used by planner.py's private helper before this story
    # promoted it here.
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "step-006.findings.json")
        captured = {}
        real_mkstemp = tempfile.mkstemp

        def spy_mkstemp(*args, **kwargs):
            fd, tmp_path = real_mkstemp(*args, **kwargs)
            captured["tmp_path"] = tmp_path
            captured["dir"] = kwargs.get("dir")
            return fd, tmp_path

        with mock.patch.object(atomic_write.tempfile, "mkstemp", side_effect=spy_mkstemp):
            atomic_write.write_json_atomic(path, {"a": 1})

        check("tmp_path" in captured, "write_json_atomic: creates its temp file via tempfile.mkstemp")
        check(
            captured.get("tmp_path") != f"{path}.tmp",
            "write_json_atomic: the temp file name is not the fixed <path>.tmp pattern",
            captured.get("tmp_path"),
        )
        check(
            captured.get("dir") == tmp,
            "write_json_atomic: the temp file is created in the destination directory",
            str(captured),
        )


def test_write_text_atomic_round_trips():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "PLANNING_FAILED")
        atomic_write.write_text_atomic(path, "planning failed\nsome detail\n")
        with open(path) as f:
            got = f.read()
        check(got == "planning failed\nsome detail\n", "write_text_atomic: round trips plain text", repr(got))
        check(not os.path.exists(path + ".tmp"), "write_text_atomic: no .tmp sibling left after a successful write")


def test_write_text_atomic_does_not_touch_a_planted_fixed_tmp_symlink():
    with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
        path = os.path.join(tmp, "prompt.md")
        victim = os.path.join(outside, "victim.txt")
        with open(victim, "w") as f:
            f.write("original host content\n")
        os.symlink(victim, f"{path}.tmp")

        atomic_write.write_text_atomic(path, "prompt text\n")

        with open(victim) as f:
            victim_content = f.read()
        check(
            victim_content == "original host content\n",
            "write_text_atomic: a symlink planted at the fixed <path>.tmp name is never followed or touched",
            victim_content,
        )
        with open(path) as f:
            got = f.read()
        check(got == "prompt text\n", "write_text_atomic: the real write still succeeds despite the planted symlink", repr(got))


def test_write_text_atomic_interrupted_write_leaves_no_file_when_none_existed():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "prompt-2.md")

        def boom(f):
            raise RuntimeError("simulated crash mid-write")

        raised = False
        try:
            atomic_write._write_atomic(path, boom)
        except RuntimeError:
            raised = True
        check(raised, "write_text_atomic: propagates the underlying write failure")
        check(not os.path.exists(path), "write_text_atomic: interrupted write with no prior file leaves nothing at final path")


def main() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
        return 1
    print("All atomic_write.py checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
