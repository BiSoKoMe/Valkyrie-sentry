"""Protected-file control credentials while the OS-authenticated broker is built.

The secret is never written before the parent directory and empty staging file
have verified restrictive access. Failure leaves HTTP control unavailable.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

from . import secure_file


def publish(data_dir: Path, token: str) -> tuple[bool, str]:
    directory = data_dir / "control"
    temporary = None
    try:
        directory.mkdir(parents=True, exist_ok=True)
        if directory.is_symlink():
            return False, "control directory must not be a symbolic link"
        ok, detail = secure_file.harden(directory, is_dir=True)
        if not ok:
            return False, detail
        fd, name = tempfile.mkstemp(prefix="credential-", dir=directory)
        temporary = Path(name)
        os.close(fd)
        ok, detail = secure_file.harden(temporary)
        if not ok:
            return False, detail
        with temporary.open("w", encoding="utf-8") as stream:
            stream.write(token)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, directory / "token")
        return True, "protected control credential published"
    except OSError as exc:
        return False, f"control credential unavailable: {type(exc).__name__}"
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass  # The staging file remains within the protected directory.
