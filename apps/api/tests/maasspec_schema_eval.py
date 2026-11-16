"""A small JSON Schema evaluator for the vendored MaaSSpec Spectrum schema. Pure, stdlib only.

It implements exactly the keywords that schema uses and raises SchemaKeywordError for any other, so a
regenerated schema that starts using a keyword this evaluator does not know fails a test instead of being
read as "accepts everything". `accepts` answers yes or no and never explains: the tests compare it with
`noctornal_api.maasspec.validate`, which is the thing under test.

Annotations (`$schema`, `$id`, `title`, `default`, `format`) assert nothing here. `format` is an annotation
in JSON Schema 2020-12 unless a validator opts in, and the schema uses it for uuid and date-time only.
"""
from __future__ import annotations

import re

ANNOTATIONS = frozenset({"$schema", "$id", "title", "default", "format", "$defs"})
ASSERTIONS = frozenset({
    "$ref", "type", "anyOf", "enum", "const", "pattern", "minimum", "maximum", "items",
    "properties", "required", "additionalProperties",
})
KNOWN = ANNOTATIONS | ASSERTIONS
TYPES = frozenset({"string", "number", "integer", "boolean", "object", "array", "null"})


class SchemaKeywordError(Exception):
    """The schema uses a keyword this evaluator does not implement."""


def check_keywords(schema, path: str = "#") -> None:
    """Walk every schema position and raise on the first keyword outside KNOWN."""
    if isinstance(schema, bool):
        return
    if not isinstance(schema, dict):
        raise SchemaKeywordError(f"{path} is neither an object nor a boolean schema")
    for key, value in schema.items():
        if key not in KNOWN:
            raise SchemaKeywordError(f"{path}: keyword {key!r} is not implemented")
        if key == "type":
            names = value if isinstance(value, list) else [value]
            for name in names:
                if name not in TYPES:
                    raise SchemaKeywordError(f"{path}: type {name!r} is not implemented")
        elif key in ("$defs", "properties"):
            for name, child in value.items():
                check_keywords(child, f"{path}/{key}/{name}")
        elif key == "items":
            check_keywords(value, f"{path}/items")
        elif key == "additionalProperties":
            check_keywords(value, f"{path}/additionalProperties")
        elif key == "anyOf":
            for index, child in enumerate(value):
                check_keywords(child, f"{path}/anyOf/{index}")


def _is_number(value) -> bool:
    return type(value) in (int, float)


def _type_ok(name: str, value) -> bool:
    if name == "string":
        return isinstance(value, str)
    if name == "boolean":
        return type(value) is bool
    if name == "null":
        return value is None
    if name == "object":
        return isinstance(value, dict)
    if name == "array":
        return isinstance(value, list)
    if name == "number":
        return _is_number(value)
    if name == "integer":
        return type(value) is int or (type(value) is float and value.is_integer())
    raise SchemaKeywordError(f"type {name!r} is not implemented")


def _same(left, right) -> bool:
    """JSON equality: True is not 1 and 1.0 is 1."""
    if type(left) is bool or type(right) is bool:
        return type(left) is type(right) and left == right
    if _is_number(left) and _is_number(right):
        return left == right
    if isinstance(left, list) and isinstance(right, list):
        return len(left) == len(right) and all(_same(a, b) for a, b in zip(left, right, strict=True))
    if isinstance(left, dict) and isinstance(right, dict):
        return left.keys() == right.keys() and all(_same(left[k], right[k]) for k in left)
    return type(left) is type(right) and left == right


def _resolve(ref: str, root: dict):
    prefix = "#/$defs/"
    if not ref.startswith(prefix) or ref[len(prefix):] not in root.get("$defs", {}):
        raise SchemaKeywordError(f"reference {ref!r} is not a local $defs reference")
    return root["$defs"][ref[len(prefix):]]


def _valid(schema, value, root: dict) -> bool:
    if schema is True:
        return True
    if schema is False:
        return False
    if "$ref" in schema and not _valid(_resolve(schema["$ref"], root), value, root):
        return False
    if "type" in schema:
        names = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_type_ok(name, value) for name in names):
            return False
    if "const" in schema and not _same(schema["const"], value):
        return False
    if "enum" in schema and not any(_same(member, value) for member in schema["enum"]):
        return False
    if "anyOf" in schema and not any(_valid(option, value, root) for option in schema["anyOf"]):
        return False
    if "pattern" in schema and isinstance(value, str) and re.search(schema["pattern"], value) is None:
        return False
    if _is_number(value):
        if "minimum" in schema and not value >= schema["minimum"]:
            return False
        if "maximum" in schema and not value <= schema["maximum"]:
            return False
    if isinstance(value, list) and "items" in schema:
        if not all(_valid(schema["items"], item, root) for item in value):
            return False
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        if any(name not in value for name in schema.get("required", ())):
            return False
        for name, item in value.items():
            if name in properties:
                if not _valid(properties[name], item, root):
                    return False
            elif "additionalProperties" in schema:
                if not _valid(schema["additionalProperties"], item, root):
                    return False
    return True


def accepts(schema: dict, instance) -> bool:
    """True when `instance` satisfies `schema`. Raises SchemaKeywordError on an unknown keyword."""
    if id(schema) not in _CHECKED:
        check_keywords(schema)
        _CHECKED[id(schema)] = schema
    return _valid(schema, instance, schema)


# Holding the schema keeps its id from being reused by another object.
_CHECKED: dict[int, dict] = {}
