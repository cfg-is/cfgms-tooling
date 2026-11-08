#!/usr/bin/env python3
"""
safefs: filesystem access to directories an agent or candidate code can write.

The supervisor runs as the host user and holds the GitHub token. Any path an
agent container could have written to -- its session dir, `out/`, the
workspace `A`, a per-run cache -- may hold a symlink planted to redirect a
supervisor write onto a host file, or a read onto host data. Every write into
such a directory goes through `write_file`; every directory the supervisor
hands to a container is created fresh by `fresh_dir`; data the supervisor must
process from such a directory is first copied out by `copy_regular_tree`.

  write_file   open the directory O_DIRECTORY|O_NOFOLLOW, unlink a stale temp
               name, create it O_CREAT|O_EXCL|O_NOFOLLOW relative to that fd,
               write, then rename within the same directory fd.
  fresh_dir    remove whatever is at the path without following links (a
               symlink is unlinked, a directory removed with the fd-based
               rmtree), then mkdir(exist_ok=False).
  copy_regular_tree
               walk with lstat semantics and copy regular files only, each
               opened O_NOFOLLOW, under a total-size cap.
  remove_tree  fd-based removal that never follows a link and makes each
               read-only directory writable through its fd before emptying it.
"""

import errno
import os
import shutil
import stat
from pathlib import Path


class UnsafePath(Exception):
    pass


def _open_dir(path):
    try:
        return os.open(str(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        raise UnsafePath(f"{path}: not a plain directory ({exc.strerror})")


def write_file(dir_path, name, data, mode=0o600):
    """Atomically write `dir_path/name` without following any symlink."""
    if "/" in name or name in ("", ".", ".."):
        raise ValueError("name must be a plain file name")
    if isinstance(data, str):
        data = data.encode("utf-8")
    tmp = f".{name}.fsm-tmp"
    dfd = _open_dir(dir_path)
    try:
        try:
            os.unlink(tmp, dir_fd=dfd)
        except FileNotFoundError:
            pass
        except IsADirectoryError:
            raise UnsafePath(f"{dir_path}/{tmp} is a directory")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=dfd)
        try:
            view = memoryview(data)
            while view:
                n = os.write(fd, view)
                view = view[n:]
            os.fsync(fd)
        finally:
            os.close(fd)
        # rename(2) replaces a symlink at `name` with the new file; it never
        # writes through it.
        os.replace(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
    finally:
        os.close(dfd)


def remove_nofollow(path):
    path = Path(path)
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return
    if stat.S_ISDIR(st.st_mode):
        if not shutil.rmtree.avoids_symlink_attacks:
            raise UnsafePath("platform rmtree is not symlink-safe")
        shutil.rmtree(path)
    else:
        os.unlink(path)


def _open_child_dir(dfd, name):
    """Open directory `name` under `dfd` without following a link. A directory
    with no read/search bit is made owner-accessible first (fchmodat with
    AT_SYMLINK_NOFOLLOW: a link swapped in is never chmod'ed through)."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        return os.open(name, flags, dir_fd=dfd)
    except PermissionError:
        try:
            os.chmod(name, 0o700, dir_fd=dfd, follow_symlinks=False)
        except (OSError, NotImplementedError):
            raise PermissionError(errno.EACCES, os.strerror(errno.EACCES), name)
        return os.open(name, flags, dir_fd=dfd)


def _clear_dir_fd(dfd, errors, freed):
    """Empty the directory open at `dfd`. Every child is reached relative to a
    directory fd and opened O_NOFOLLOW: a symlink is unlinked, never followed.
    Each directory is made owner-writable through its fd first, so read-only
    trees (a Go module cache) can be emptied."""
    try:
        os.fchmod(dfd, 0o700)
    except OSError as exc:
        errors.append(f"fchmod: {exc.strerror}")
    try:
        names = os.listdir(dfd)
    except OSError as exc:
        errors.append(f"listdir: {exc.strerror}")
        return
    for name in names:
        try:
            st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        except OSError as exc:
            errors.append(f"{name}: {exc.strerror}")
            continue
        if stat.S_ISDIR(st.st_mode):
            try:
                cfd = _open_child_dir(dfd, name)
            except OSError as exc:
                errors.append(f"{name}: {exc.strerror}")
                continue
            try:
                _clear_dir_fd(cfd, errors, freed)
            finally:
                os.close(cfd)
            try:
                os.rmdir(name, dir_fd=dfd)
            except OSError as exc:
                errors.append(f"{name}: {exc.strerror}")
            continue
        try:
            os.unlink(name, dir_fd=dfd)
        except FileNotFoundError:
            continue
        except OSError as exc:
            errors.append(f"{name}: {exc.strerror}")
            continue
        if stat.S_ISREG(st.st_mode):
            freed[0] += st.st_size


def remove_tree(path):
    """Remove `path` and everything under it without following any symlink.

    For trees candidate code or an agent wrote (a run's validator cache):
    read-only files and directories are removed (each directory is chmod'ed
    u+rwx through its own fd first), a symlink anywhere -- `path` itself
    included -- is unlinked and its target left alone. Never raises on a
    filesystem error. Returns (bytes_freed, errors); `path` is gone when
    `errors` is empty.
    """
    path = Path(path)
    errors, freed = [], [0]
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return 0, []
    except OSError as exc:
        return 0, [f"lstat: {exc.strerror}"]
    if not stat.S_ISDIR(st.st_mode):
        try:
            os.unlink(path)
        except OSError as exc:
            errors.append(f"unlink: {exc.strerror}")
        return 0, errors
    try:
        dfd = _open_dir(path)
    except UnsafePath as exc:
        return 0, [str(exc)]
    try:
        _clear_dir_fd(dfd, errors, freed)
    finally:
        os.close(dfd)
    try:
        os.rmdir(path)
    except OSError as exc:
        errors.append(f"rmdir: {exc.strerror}")
    return freed[0], errors


def fresh_dir(path, mode=0o700):
    """Replace whatever is at `path` with a new, empty directory."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    remove_nofollow(path)
    path.mkdir(mode=mode, exist_ok=False)
    return path


def ensure_plain_dir(path):
    """`path` as a real directory (not a symlink); recreated when it is not."""
    path = Path(path)
    try:
        st = os.lstat(path)
        if stat.S_ISDIR(st.st_mode):
            return path
    except FileNotFoundError:
        pass
    return fresh_dir(path)


def copy_regular_tree(src, dst, max_total=512 * 1024 * 1024, max_files=20000):
    """Copy regular files under `src` into a fresh `dst`; never follows links.

    Returns the number of files copied. Stops copying at the caps.
    """
    fresh_dir(dst)
    total = files = 0
    try:
        root_fd = _open_dir(src)
    except UnsafePath:
        return 0
    os.close(root_fd)
    stack = [""]
    while stack:
        rel = stack.pop()
        sdir = os.path.join(str(src), rel) if rel else str(src)
        try:
            dfd = _open_dir(sdir)
        except UnsafePath:
            continue
        try:
            for name in os.listdir(dfd):
                try:
                    st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
                except OSError:
                    continue
                child = f"{rel}/{name}" if rel else name
                if stat.S_ISDIR(st.st_mode):
                    stack.append(child)
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue
                if files >= max_files or total + st.st_size > max_total:
                    return files
                try:
                    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
                except OSError:
                    continue
                try:
                    if not stat.S_ISREG(os.fstat(fd).st_mode):
                        continue
                    out = Path(dst) / child
                    out.parent.mkdir(parents=True, exist_ok=True)
                    with open(out, "xb") as fh:
                        while True:
                            chunk = os.read(fd, 1 << 20)
                            if not chunk:
                                break
                            fh.write(chunk)
                finally:
                    os.close(fd)
                files += 1
                total += st.st_size
        finally:
            os.close(dfd)
    return files
