"""Private local output. No upload paths or shell execution."""

import os
from pathlib import Path
import stat
import tempfile


def private_directory(path: Path) -> Path:
    path = path.absolute()
    # Refuse symlinks in all components; do not chmod someone else's directory.
    if any(p.is_symlink() for p in [path, *path.parents]):
        raise ValueError("output path must not contain symlinks")
    if not path.exists():
        path.mkdir(mode=0o700, parents=True)
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise ValueError("output directory must be owned by the current user")
    if info.st_mode & 0o077:
        raise ValueError("output directory must already have mode 0700")
    return path


def new_run(root: Path, prefix: str) -> Path:
    return Path(tempfile.mkdtemp(prefix=prefix, dir=private_directory(root)))


def write_private(path: Path, content: str) -> None:
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as handle:
        handle.write(content)
