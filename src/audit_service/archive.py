# Copyright (C) 2026 James Hickman
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Encrypted archive stores for aged audit rows (§7).

See design_documents/SPEC_retention_and_archival.md. Archives are Fernet tokens,
so no audit row is ever written to object storage in the clear. The production
store is the MAIN content bucket (the core's own), where each scope gets a
reserved virtual folder beside the core's ``<tenant>/<uid>/<version>`` keys:

    [<prefix>/]<scope>/<folder>/<YYYY>/<MM>/<run id>/part-<NNNNN>.ndjson.enc
    [<prefix>/]<scope>/<folder>/<YYYY>/<MM>/<run id>/manifest.json.enc

Objects are write-once: run ids are unique, and nothing here overwrites or
deletes. The local backend uses the identical layout under an ABSOLUTE root.
"""
from __future__ import annotations

import os
import re


class ArchiveError(Exception):
    pass


def make_cipher(key: str):
    """A MultiFernet over the comma-separated keys: the first encrypts, every
    key decrypts, so a key can be rotated without stranding older archives."""
    from cryptography.fernet import Fernet, MultiFernet
    keys = [k.strip() for k in (key or "").split(",") if k.strip()]
    if not keys:
        raise ArchiveError("FILEENGINE_AUDIT_ARCHIVE_KEY is not set — refusing to "
                           "archive audit data unencrypted")
    try:
        return MultiFernet([Fernet(k.encode()) for k in keys])
    except ValueError as e:  # malformed key: fail before anything is read
        raise ArchiveError(f"FILEENGINE_AUDIT_ARCHIVE_KEY is not a valid Fernet key: {e}")


# A reserved name must not be able to collide with a tenant id or a file uid.
_RESERVED = re.compile(r"^_[A-Za-z0-9_.-]{1,62}$")


def validate_reserved(name: str, what: str) -> str:
    if not _RESERVED.match(name or ""):
        raise ArchiveError(f"{what} {name!r} must start with '_' and use only "
                           "[A-Za-z0-9_.-] — it shares a namespace with tenant ids")
    return name


def segment_prefix(scope_id: str, folder: str, year: int, month: int, run_id: str) -> str:
    return f"{scope_id}/{folder}/{year:04d}/{month:02d}/{run_id}"


def part_key(segment: str, part_no: int) -> str:
    return f"{segment}/part-{part_no:05d}.ndjson.enc"


def manifest_key(segment: str) -> str:
    return f"{segment}/manifest.json.enc"


class LocalArchive:
    def __init__(self, base_dir: str):
        if not base_dir or not os.path.isabs(base_dir):
            # The trap this job fell into before: a relative directory inside a
            # --rm container verifies perfectly and is deleted with it.
            raise ArchiveError(f"AUDIT_ARCHIVE_DIR must be an absolute path, got {base_dir!r}")
        self.base = base_dir

    def _path(self, key: str) -> str:
        path = os.path.normpath(os.path.join(self.base, key))
        if not path.startswith(os.path.normpath(self.base) + os.sep):
            raise ArchiveError(f"archive key escapes the archive root: {key!r}")
        return path

    def put(self, key: str, data: bytes) -> None:
        path = self._path(key)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)

    def get(self, key: str) -> bytes:
        with open(self._path(key), "rb") as f:
            return f.read()

    def exists(self, key: str) -> bool:
        return os.path.isfile(self._path(key))

    def object_key(self, key: str) -> str:
        return key

    def get_object(self, object_key: str) -> bytes:
        return self.get(object_key)

    def list(self, prefix: str):
        root = os.path.dirname(self._path(prefix.rstrip("/") + "/placeholder"))
        for dirpath, _, files in os.walk(root):
            for name in files:
                if not name.endswith(".tmp"):
                    yield os.path.relpath(os.path.join(dirpath, name), self.base)


class S3Archive:
    def __init__(self, bucket: str, prefix: str = "", endpoint: str = "", *,
                 region: str = "", access_key: str = "", secret_key: str = "",
                 path_style: bool = False):
        if not bucket:
            raise ArchiveError("no archive bucket: set FILEENGINE_S3_BUCKET (the main "
                               "store) or AUDIT_ARCHIVE_S3_BUCKET")
        import boto3
        from botocore.config import Config as BotoConfig
        self.bucket = bucket
        self.prefix = prefix.strip("/")
        self._s3 = boto3.client(
            "s3", endpoint_url=endpoint or None, region_name=region or None,
            aws_access_key_id=access_key or None, aws_secret_access_key=secret_key or None,
            config=BotoConfig(s3={"addressing_style": "path" if path_style else "auto"},
                              retries={"max_attempts": 5, "mode": "standard"}))

    def _key(self, key: str) -> str:
        return f"{self.prefix}/{key}" if self.prefix else key

    def object_key(self, key: str) -> str:
        """The key as it exists in the bucket — what the catalog records, so the
        backup's restore manifest names the real object."""
        return self._key(key)

    def put(self, key: str, data: bytes) -> None:
        self._s3.put_object(Bucket=self.bucket, Key=self._key(key), Body=data,
                            ContentType="application/octet-stream")

    def get(self, key: str) -> bytes:
        return self.get_object(self._key(key))

    def get_object(self, object_key: str) -> bytes:
        """Read by the key AS CATALOGUED (prefix included)."""
        return self._s3.get_object(Bucket=self.bucket, Key=object_key)["Body"].read()

    def exists(self, key: str) -> bool:
        import botocore
        try:
            self._s3.head_object(Bucket=self.bucket, Key=self._key(key))
            return True
        except botocore.exceptions.ClientError:
            return False

    def list(self, prefix: str):
        strip = len(self.prefix) + 1 if self.prefix else 0
        pages = self._s3.get_paginator("list_objects_v2").paginate(
            Bucket=self.bucket, Prefix=self._key(prefix))
        for page in pages:
            for obj in page.get("Contents", []):
                yield obj["Key"][strip:]


def make_archive(config):
    backend = config.archive_backend
    if backend == "local":
        return LocalArchive(config.archive_dir)
    if backend == "s3":
        return S3Archive(config.archive_s3_bucket, config.archive_s3_prefix,
                         config.archive_s3_endpoint, region=config.archive_s3_region,
                         access_key=config.archive_s3_access_key,
                         secret_key=config.archive_s3_secret_key,
                         path_style=config.archive_s3_path_style)
    if backend == "none":
        return None
    raise ArchiveError(f"unknown AUDIT_ARCHIVE_BACKEND: {backend!r}")
