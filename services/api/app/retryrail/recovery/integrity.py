"""Canonical content identity helpers shared across recovery boundaries."""

import hashlib
import json
from collections.abc import Mapping
from typing import Any, Final

from pydantic import BaseModel
from pydantic_core import to_jsonable_python

_IDENTITY_SEPARATOR: Final = "\x1f"


def canonical_sha256(value: BaseModel | Mapping[str, object]) -> str:
    """Hash a canonical, ASCII JSON representation of a typed recovery fact."""

    document: Any = (
        value.model_dump(mode="json")
        if isinstance(value, BaseModel)
        else to_jsonable_python(dict(value))
    )
    encoded = json.dumps(
        document,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def stable_identifier(kind: str, merchant_id: str, unique_key: str) -> str:
    """Derive a deterministic opaque identifier without exposing scoped inputs."""

    material = _IDENTITY_SEPARATOR.join((kind, merchant_id, unique_key)).encode()
    return f"{kind}_{hashlib.sha256(material).hexdigest()}"
