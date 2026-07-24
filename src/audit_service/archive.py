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

"""Encrypted archive sinks for aged audit partitions (§7).

Archives are Fernet-encrypted at rest, so an audit day is never written to object
storage in the clear. Two backends: local directory and S3 (also S3-compatible via
an endpoint). Keys are ``<tenant-or-global>/audit_log_pYYYYMMDD.ndjson.enc``.
"""
from __future__ import annotations

import os


class ArchiveError(Exception):
    pass


def make_cipher(key: str):
    from cryptography.fernet import Fernet
    if not key:
        raise ArchiveError("FILEENGINE_AUDIT_ARCHIVE_KEY is not set — refusing to "
                           "archive audit data unencrypted")
    return Fernet(key.encode() if isinstance(key, str) else key)


class LocalArchive:
    def __init__(self, base_dir: str):
        self.base = base_dir

    def put(self, key: str, data: bytes) -> None:
        path = os.path.join(self.base, key)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)

    def get(self, key: str) -> bytes:
        with open(os.path.join(self.base, key), "rb") as f:
            return f.read()

    def exists(self, key: str) -> bool:
        return os.path.isfile(os.path.join(self.base, key))


class S3Archive:
    def __init__(self, bucket: str, prefix: str = "", endpoint: str = ""):
        import boto3
        self.bucket = bucket
        self.prefix = prefix.strip("/")
        self._s3 = boto3.client("s3", endpoint_url=endpoint or None)

    def _key(self, key: str) -> str:
        return f"{self.prefix}/{key}" if self.prefix else key

    def put(self, key: str, data: bytes) -> None:
        self._s3.put_object(Bucket=self.bucket, Key=self._key(key), Body=data)

    def get(self, key: str) -> bytes:
        return self._s3.get_object(Bucket=self.bucket, Key=self._key(key))["Body"].read()

    def exists(self, key: str) -> bool:
        import botocore
        try:
            self._s3.head_object(Bucket=self.bucket, Key=self._key(key))
            return True
        except botocore.exceptions.ClientError:
            return False


def make_archive(config):
    backend = config.archive_backend
    if backend == "local":
        return LocalArchive(config.archive_dir)
    if backend == "s3":
        return S3Archive(config.archive_s3_bucket, config.archive_s3_prefix,
                         config.archive_s3_endpoint)
    if backend == "none":
        return None
    raise ArchiveError(f"unknown AUDIT_ARCHIVE_BACKEND: {backend!r}")
