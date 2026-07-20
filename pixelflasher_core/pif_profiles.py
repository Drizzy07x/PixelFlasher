"""UI-independent PIF transformations and durable local favorites."""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Literal, cast

PifInputFormat = Literal["json", "prop"]
PifOutputFormat = Literal["json", "prop", "framework_patcher"]
MAX_PIF_PROFILE_BYTES: Final = 32 * 1024
MAX_PIF_FAVORITES: Final = 512
MAX_PIF_LABEL_LENGTH: Final = 128
_KEY = re.compile(r"^[A-Za-z_*][A-Za-z0-9_.*-]{0,127}$")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_LABEL_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_FINGERPRINT = re.compile(
    r"^(?P<brand>[^/]+)/(?P<product>[^/]+)/(?P<device>[^:]+):"
    r"(?P<release>[^/]+)/(?P<id>[^/]+)/(?P<incremental>[^:]+):"
    r"(?P<type>[^/]+)/(?P<tags>[^/]+)$"
)
_ALIASES: Final = {
    "MANUFACTURER": "MANUFACTURER", "ro.product.manufacturer": "MANUFACTURER",
    "MODEL": "MODEL", "ro.product.model": "MODEL",
    "FINGERPRINT": "FINGERPRINT", "ro.build.fingerprint": "FINGERPRINT",
    "BRAND": "BRAND", "ro.product.brand": "BRAND",
    "PRODUCT": "PRODUCT", "ro.product.name": "PRODUCT",
    "DEVICE": "DEVICE", "ro.product.device": "DEVICE",
    "SECURITY_PATCH": "SECURITY_PATCH", "*.security_patch": "SECURITY_PATCH",
    "ro.build.version.security_patch": "SECURITY_PATCH",
    "FIRST_API_LEVEL": "FIRST_API_LEVEL", "*api_level": "FIRST_API_LEVEL",
    "ro.product.first_api_level": "FIRST_API_LEVEL",
    "BUILD_ID": "ID", "ID": "ID", "ro.build.id": "ID",
    "VNDK_VERSION": "VNDK_VERSION", "*.vndk_version": "VNDK_VERSION",
    "ro.vndk.version": "VNDK_VERSION",
    "INCREMENTAL": "INCREMENTAL", "ro.build.version.incremental": "INCREMENTAL",
    "TYPE": "TYPE", "ro.build.type": "TYPE",
    "TAGS": "TAGS", "ro.build.tags": "TAGS",
    "RELEASE": "RELEASE", "ro.build.version.release": "RELEASE",
}
_ORDER: Final = (
    "MANUFACTURER", "MODEL", "FINGERPRINT", "BRAND", "PRODUCT", "DEVICE",
    "RELEASE", "ID", "INCREMENTAL", "TYPE", "TAGS", "SECURITY_PATCH",
    "FIRST_API_LEVEL", "VNDK_VERSION",
)


class PifProfileError(ValueError):
    """A PIF transformation or repository operation failed closed."""


@dataclass(frozen=True, slots=True)
class PifTransformation:
    content: str
    format: PifOutputFormat
    sha256: str
    size: int
    field_count: int

    def to_public_dict(self) -> dict[str, object]:
        return {"schemaVersion": 1, "format": self.format, "content": self.content,
                "sha256": self.sha256, "size": self.size,
                "fieldCount": self.field_count, "bounded": True}


@dataclass(frozen=True, slots=True)
class PifFavorite:
    favorite_id: str
    label: str
    created_at: str
    sha256: str
    content: str

    def to_metadata_dict(self) -> dict[str, object]:
        return {"favoriteId": self.favorite_id, "label": self.label,
                "createdAt": self.created_at, "sha256": self.sha256,
                "size": len(self.content.encode("utf-8"))}

    def to_public_dict(self) -> dict[str, object]:
        return {**self.to_metadata_dict(), "content": self.content}


class PifProfileTransformer:
    """Parse and transform bounded PIF documents deterministically."""

    def transform(
        self, content: str, *, input_format: PifInputFormat,
        output_format: PifOutputFormat, normalize: bool = False,
        keep_unknown: bool = True, sort_keys: bool = False,
        first_api: int | None = None,
    ) -> PifTransformation:
        values = self.parse(content, input_format=input_format)
        if normalize:
            values = self._normalize(values, keep_unknown=keep_unknown)
        if first_api is not None:
            if isinstance(first_api, bool) or not 1 <= first_api <= 99:
                raise PifProfileError("first API level must be between 1 and 99")
            values["FIRST_API_LEVEL"] = str(first_api)
        if output_format == "json":
            output = json.dumps(values, ensure_ascii=False, indent=2, sort_keys=sort_keys) + "\n"
        elif output_format == "prop":
            items = sorted(values.items()) if sort_keys else values.items()
            output = "".join(f"{key}={self._prop_value(value)}\n" for key, value in items)
        elif output_format == "framework_patcher":
            output = self._framework_patcher(values)
        else:
            raise PifProfileError("unsupported PIF output format")
        raw = output.encode("utf-8")
        if len(raw) > MAX_PIF_PROFILE_BYTES:
            raise PifProfileError("transformed PIF document exceeds 32 KiB")
        return PifTransformation(output, output_format, hashlib.sha256(raw).hexdigest(), len(raw), len(values))

    def parse(self, content: str, *, input_format: PifInputFormat) -> dict[str, str]:
        if not isinstance(content, str):
            raise PifProfileError("PIF content must be text")
        raw = content.encode("utf-8")
        if not raw or len(raw) > MAX_PIF_PROFILE_BYTES or _CONTROL.search(content):
            raise PifProfileError("PIF content is empty, oversized, or contains control bytes")
        if input_format == "json":
            try:
                parsed: object = json.loads(content)
            except (json.JSONDecodeError, UnicodeError) as error:
                raise PifProfileError("PIF JSON is invalid") from error
            if not isinstance(parsed, dict) or not parsed:
                raise PifProfileError("PIF JSON must be a non-empty object")
            values: dict[str, str] = {}
            for key, value in cast(dict[object, object], parsed).items():
                if not isinstance(key, str) or not _KEY.fullmatch(key):
                    raise PifProfileError("PIF JSON contains an invalid key")
                if not isinstance(value, (str, int, float, bool)) or (
                    isinstance(value, float) and not value.is_integer()
                ):
                    raise PifProfileError("PIF JSON values must be scalar")
                values[key] = str(value).lower() if isinstance(value, bool) else str(value)
            return values
        if input_format != "prop":
            raise PifProfileError("unsupported PIF input format")
        values = {}
        for source in content.splitlines():
            line = source.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                raise PifProfileError("PIF property line is missing equals")
            key, value = line.split("=", 1)
            key = key.strip()
            if not _KEY.fullmatch(key) or key in values:
                raise PifProfileError("PIF properties contain an invalid or duplicate key")
            values[key] = value.strip()
        if not values:
            raise PifProfileError("PIF properties are empty")
        return values

    @staticmethod
    def _normalize(values: Mapping[str, str], *, keep_unknown: bool) -> dict[str, str]:
        normalized: dict[str, str] = {}
        unknown: dict[str, str] = {}
        for key, value in values.items():
            canonical = _ALIASES.get(key)
            if canonical:
                normalized[canonical] = value
            elif keep_unknown:
                unknown[key] = value
        match = _FINGERPRINT.fullmatch(normalized.get("FINGERPRINT", ""))
        if match:
            derived = {"BRAND": match["brand"], "PRODUCT": match["product"],
                       "DEVICE": match["device"], "RELEASE": match["release"],
                       "ID": match["id"], "INCREMENTAL": match["incremental"],
                       "TYPE": match["type"], "TAGS": match["tags"]}
            for key, value in derived.items():
                normalized.setdefault(key, value)
        ordered = {key: normalized[key] for key in _ORDER if normalized.get(key, "") != ""}
        ordered.update(unknown)
        if not ordered:
            raise PifProfileError("PIF normalization produced no supported fields")
        return ordered

    @staticmethod
    def _prop_value(value: str) -> str:
        if "\n" in value or "\r" in value or _CONTROL.search(value):
            raise PifProfileError("PIF property values must be single-line text")
        return value

    @staticmethod
    def _framework_patcher(values: Mapping[str, str]) -> str:
        lines = ["// PixelFlasher FrameworkPatcher profile"]
        for key in _ORDER[:12]:
            value = values.get(key, "").replace("\\", "\\\\").replace('"', '\\"')
            lines.append(f'map.put("{key}", "{value}");')
        return "\n".join(lines) + "\n"


class PifFavoritesRepository:
    """Bounded atomic JSON repository with idempotent 9.x import."""

    def __init__(self, path: str | Path, *, legacy_path: str | Path | None = None) -> None:
        self.path = Path(path).expanduser().resolve(strict=False)
        self.legacy_path = Path(legacy_path).expanduser().resolve(strict=False) if legacy_path else None
        self._lock = threading.RLock()
        self._transformer = PifProfileTransformer()
        self._favorites: dict[str, PifFavorite] = {}
        self._revision = 0
        self._load()
        if not self._favorites:
            self._import_legacy_once()

    @property
    def revision(self) -> int:
        with self._lock:
            return self._revision

    def list(self) -> tuple[PifFavorite, ...]:
        with self._lock:
            return tuple(sorted(self._favorites.values(), key=lambda item: (item.label.casefold(), item.favorite_id)))

    def get(self, favorite_id: str) -> PifFavorite:
        with self._lock:
            try:
                return self._favorites[favorite_id]
            except KeyError as error:
                raise PifProfileError("PIF favorite does not exist") from error

    def save(self, label: str, content: str) -> PifFavorite:
        clean_label = self._label(label)
        transformed = self._transformer.transform(content, input_format="json", output_format="json", sort_keys=True)
        with self._lock:
            existing = self._favorites.get(transformed.sha256)
            created = existing.created_at if existing else datetime.now(UTC).isoformat(timespec="seconds")
            favorite = PifFavorite(transformed.sha256, clean_label, created, transformed.sha256, transformed.content)
            updated = dict(self._favorites)
            updated[favorite.favorite_id] = favorite
            if len(updated) > MAX_PIF_FAVORITES:
                raise PifProfileError("PIF favorites limit reached")
            self._persist(updated, self._revision + 1)
            return favorite

    def delete(self, favorite_id: str) -> PifFavorite:
        if not re.fullmatch(r"[0-9a-f]{64}", favorite_id):
            raise PifProfileError("PIF favorite id is invalid")
        with self._lock:
            try:
                removed = self._favorites[favorite_id]
            except KeyError as error:
                raise PifProfileError("PIF favorite does not exist") from error
            updated = dict(self._favorites)
            del updated[favorite_id]
            self._persist(updated, self._revision + 1)
            return removed

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            if self.path.stat().st_size > 20 * 1024 * 1024:
                raise PifProfileError("PIF favorites repository is oversized")
            raw_document: object = json.loads(self.path.read_text(encoding="utf-8"))
            document = cast(dict[str, object], raw_document) if isinstance(raw_document, dict) else None
            if not isinstance(document, dict) or set(document) != {"schemaVersion", "revision", "favorites"}:
                raise PifProfileError("PIF favorites repository schema is invalid")
            revision: object = document["revision"]
            rows: object = document["favorites"]
            if document["schemaVersion"] != 1 or not isinstance(revision, int) or revision < 0 or not isinstance(rows, list):
                raise PifProfileError("PIF favorites repository metadata is invalid")
            typed_rows = cast(list[object], rows)
            if len(typed_rows) > MAX_PIF_FAVORITES:
                raise PifProfileError("PIF favorites repository exceeds its item limit")
            loaded: dict[str, PifFavorite] = {}
            for row in typed_rows:
                favorite = self._decode(row)
                if favorite.favorite_id in loaded:
                    raise PifProfileError("PIF favorites repository contains duplicates")
                loaded[favorite.favorite_id] = favorite
        except (OSError, json.JSONDecodeError) as error:
            raise PifProfileError("PIF favorites repository is unreadable") from error
        self._favorites, self._revision = loaded, revision

    def _import_legacy_once(self) -> None:
        source = self.legacy_path
        if source is None or not source.is_file() or self.path.exists():
            return
        try:
            raw = source.read_bytes()
            decoded: object = json.loads(raw.decode("latin-1")) if len(raw) <= 20 * 1024 * 1024 else None
            legacy = cast(dict[object, object], decoded) if isinstance(decoded, dict) else None
        except (OSError, UnicodeError, json.JSONDecodeError):
            return
        if not isinstance(legacy, dict):
            return
        imported: dict[str, PifFavorite] = {}
        for value in legacy.values():
            if len(imported) >= MAX_PIF_FAVORITES or not isinstance(value, dict):
                break
            row = cast(dict[object, object], value)
            label: object = row.get("label")
            pif: object = row.get("pif")
            if not isinstance(label, str) or not isinstance(pif, dict):
                continue
            try:
                item = self._transformer.transform(json.dumps(pif, ensure_ascii=False), input_format="json", output_format="json", sort_keys=True)
                clean_label = self._label(label)
            except (PifProfileError, TypeError, ValueError):
                continue
            legacy_date: object = row.get("date_added")
            created = legacy_date if isinstance(legacy_date, str) and 1 <= len(legacy_date) <= 64 and not _LABEL_CONTROL.search(legacy_date) else "legacy"
            imported[item.sha256] = PifFavorite(item.sha256, clean_label, created, item.sha256, item.content)
        if imported:
            self._persist(imported, 1)

    def _decode(self, row: object) -> PifFavorite:
        fields = {"favoriteId", "label", "createdAt", "sha256", "content"}
        if not isinstance(row, dict):
            raise PifProfileError("PIF favorite row schema is invalid")
        raw_values = cast(dict[object, object], row)
        if set(raw_values) != fields:
            raise PifProfileError("PIF favorite row schema is invalid")
        values = cast(dict[str, object], raw_values)
        favorite_id, created, content = values["favoriteId"], values["createdAt"], values["content"]
        if (not isinstance(favorite_id, str) or not re.fullmatch(r"[0-9a-f]{64}", favorite_id)
                or values["sha256"] != favorite_id or not isinstance(created, str)
                or not 1 <= len(created) <= 64 or _LABEL_CONTROL.search(created)
                or not isinstance(content, str)):
            raise PifProfileError("PIF favorite row metadata is invalid")
        transformed = self._transformer.transform(content, input_format="json", output_format="json", sort_keys=True)
        if transformed.sha256 != favorite_id or transformed.content != content:
            raise PifProfileError("PIF favorite content hash is invalid")
        return PifFavorite(favorite_id, self._label(values["label"]), created, favorite_id, content)

    def _persist(self, favorites: Mapping[str, PifFavorite], revision: int) -> None:
        document = {"schemaVersion": 1, "revision": revision, "favorites": [
            {"favoriteId": item.favorite_id, "label": item.label, "createdAt": item.created_at,
             "sha256": item.sha256, "content": item.content}
            for item in sorted(favorites.values(), key=lambda row: row.favorite_id)]}
        encoded = (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(f".{self.path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
        try:
            with temporary.open("xb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            if os.name != "nt":
                descriptor = os.open(self.path.parent, os.O_RDONLY)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
        except OSError as error:
            temporary.unlink(missing_ok=True)
            raise PifProfileError("PIF favorites repository could not be saved") from error
        self._favorites, self._revision = dict(favorites), revision

    @staticmethod
    def _label(value: object) -> str:
        if not isinstance(value, str):
            raise PifProfileError("PIF favorite label must be text")
        label = value.strip()
        if not 1 <= len(label) <= MAX_PIF_LABEL_LENGTH or _LABEL_CONTROL.search(label):
            raise PifProfileError("PIF favorite label is invalid")
        return label
