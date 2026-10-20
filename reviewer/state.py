"""Atomic local records and exclusive same-filesystem claims, not distributed locks."""
import hashlib
import json
import os
from pathlib import Path
import tempfile


def save_atomic(path, record):
    path = Path(path)
    data = (json.dumps(record, ensure_ascii=False, sort_keys=True,
                       separators=(',', ':'), allow_nan=False) + '\n').encode('utf-8')
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.pending-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return hashlib.sha256(data).hexdigest()


def claim(key, intent):
    path = Path(key)
    data = json.dumps(intent, ensure_ascii=False, allow_nan=False).encode('utf-8')
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open('xb') as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
    except FileExistsError:
        raise RuntimeError('NOT_AUTHORIZED') from None
    return dict(intent)
