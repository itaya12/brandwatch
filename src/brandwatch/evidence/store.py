"""Content-addressed artifact storage (spec §1 "Evidence Store": object storage + hashes in DB).

Phase 1 ships a local-filesystem implementation. The DB row (``evidence.artifact_location`` +
``content_sha256``) is the source of truth; an artifact is stored once per content hash, so the
same screenshot observed twice costs one file. Object storage (S3-style) later implements the
same ``EvidenceStore`` Protocol.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass(frozen=True, slots=True)
class StoredArtifact:
    sha256: str
    location: str  # opaque locator understood by the store ("local://ab/cd/<sha>.png")
    size_bytes: int
    content_type: str


class EvidenceStore(Protocol):
    def delete(self, location: str) -> bool: ...

    def put(self, content: bytes, *, content_type: str, suffix: str) -> StoredArtifact: ...
    def get(self, location: str) -> bytes: ...
    def exists(self, location: str) -> bool: ...


class LocalEvidenceStore:
    SCHEME = "local://"

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, location: str) -> Path:
        if not location.startswith(self.SCHEME):
            raise ValueError(f"not a local artifact location: {location}")
        rel = location[len(self.SCHEME) :]
        path = (self.root / rel).resolve()
        if self.root.resolve() not in path.parents:
            raise ValueError("artifact location escapes the store root")
        return path

    def delete(self, location: str) -> bool:
        """Remove an artifact file (used only by the admin purge). Missing files are fine."""
        try:
            path = self._path(location)
        except ValueError:
            return False
        if path.is_file():
            path.unlink()
            return True
        return False

    def put(self, content: bytes, *, content_type: str, suffix: str) -> StoredArtifact:
        sha = hashlib.sha256(content).hexdigest()
        suffix = suffix if suffix.startswith(".") else f".{suffix}"
        rel = f"{sha[:2]}/{sha[2:4]}/{sha}{suffix}"
        path = self.root / rel
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(path.suffix + ".tmp")
            tmp.write_bytes(content)
            tmp.replace(path)
        return StoredArtifact(
            sha256=sha,
            location=f"{self.SCHEME}{rel}",
            size_bytes=len(content),
            content_type=content_type,
        )

    def get(self, location: str) -> bytes:
        return self._path(location).read_bytes()

    def exists(self, location: str) -> bool:
        try:
            return self._path(location).exists()
        except ValueError:
            return False
