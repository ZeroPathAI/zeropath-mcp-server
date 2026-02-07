"""
Minimal JSON Schema validator for manifest-driven client-side validation.

We intentionally implement only a small subset of JSON Schema keywords that we
expect to appear in the MCP manifest emitted by the ZeroPath frontend.

If the schema uses features we don't support, we fail fast with an explicit
error so we don't silently "validate" incorrectly.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any


JsonObject = dict[str, Any]


@dataclass(frozen=True)
class ValidationIssue:
    path: str
    message: str

    def to_dict(self) -> JsonObject:
        return {"path": self.path, "message": self.message}


class UnsupportedSchemaError(RuntimeError):
    pass


def _json_pointer_get(root: Any, ref: str) -> Any:
    if not ref.startswith("#/"):
        raise UnsupportedSchemaError(f"Only local JSON pointer $ref is supported (got {ref!r})")

    node: Any = root
    for raw_part in ref[2:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict) and part in node:
            node = node[part]
            continue
        if isinstance(node, list):
            try:
                idx = int(part)
            except ValueError as exc:
                raise UnsupportedSchemaError(f"Invalid list index in $ref {ref!r}: {part!r}") from exc
            try:
                node = node[idx]
            except IndexError as exc:
                raise UnsupportedSchemaError(f"List index out of range in $ref {ref!r}: {idx}") from exc
            continue
        raise UnsupportedSchemaError(f"Unresolvable $ref {ref!r} at token {part!r}")

    return node


def _is_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value: Any) -> bool:
    return (isinstance(value, (int, float)) and not isinstance(value, bool))


def _type_matches(value: Any, typ: str) -> bool:
    if typ == "object":
        return isinstance(value, dict)
    if typ == "array":
        return isinstance(value, list)
    if typ == "string":
        return isinstance(value, str)
    if typ == "integer":
        return _is_integer(value)
    if typ == "number":
        return _is_number(value)
    if typ == "boolean":
        return isinstance(value, bool)
    if typ == "null":
        return value is None
    raise UnsupportedSchemaError(f"Unsupported JSON Schema type {typ!r}")


def validate(
    instance: Any,
    schema: JsonObject,
    *,
    root_schema: Any | None = None,
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    # $ref is resolved relative to the root schema. When validating a tool's
    # per-procedure schema, callers may provide a broader root (e.g. the full
    # manifest) so shared definitions can be referenced.
    resolved_root = root_schema if root_schema is not None else schema
    _validate(instance, schema, path="", issues=issues, root_schema=resolved_root, ref_stack=set())
    return issues


def _validate(
    instance: Any,
    schema: Any,
    *,
    path: str,
    issues: list[ValidationIssue],
    root_schema: Any,
    ref_stack: set[str],
) -> None:
    if schema is True or schema is None:
        return
    if schema is False:
        issues.append(ValidationIssue(path, "Value is not allowed by schema"))
        return
    if not isinstance(schema, dict):
        raise UnsupportedSchemaError("Schema nodes must be objects/booleans")

    ref = schema.get("$ref")
    if ref is not None:
        if not isinstance(ref, str):
            raise UnsupportedSchemaError("$ref must be a string")
        if ref in ref_stack:
            raise UnsupportedSchemaError(f"Recursive $ref detected: {ref!r}")
        ref_stack.add(ref)
        try:
            target = _json_pointer_get(root_schema, ref)
        finally:
            ref_stack.remove(ref)
        _validate(instance, target, path=path, issues=issues, root_schema=root_schema, ref_stack=ref_stack)
        return

    # Composition
    for key in ("allOf", "anyOf", "oneOf"):
        if key in schema and not isinstance(schema[key], list):
            raise UnsupportedSchemaError(f"{key} must be a list")

    if "allOf" in schema:
        for sub in schema["allOf"]:
            _validate(instance, sub, path=path, issues=issues, root_schema=root_schema, ref_stack=ref_stack)

    if "anyOf" in schema:
        ok = False
        for sub in schema["anyOf"]:
            tmp: list[ValidationIssue] = []
            _validate(instance, sub, path=path, issues=tmp, root_schema=root_schema, ref_stack=ref_stack)
            if not tmp:
                ok = True
                break
        if not ok:
            issues.append(ValidationIssue(path, "Value does not match anyOf schemas"))

    if "oneOf" in schema:
        matches = 0
        for sub in schema["oneOf"]:
            tmp = []
            _validate(instance, sub, path=path, issues=tmp, root_schema=root_schema, ref_stack=ref_stack)
            if not tmp:
                matches += 1
        if matches != 1:
            issues.append(ValidationIssue(path, f"Value must match exactly one schema (matched {matches})"))

    if "const" in schema:
        if instance != schema["const"]:
            issues.append(ValidationIssue(path, "Value does not match const"))

    if "enum" in schema:
        enum = schema["enum"]
        if not isinstance(enum, list):
            raise UnsupportedSchemaError("enum must be a list")
        if instance not in enum:
            issues.append(ValidationIssue(path, "Value is not in enum"))

    typ = schema.get("type")
    if typ is not None:
        if isinstance(typ, str):
            allowed_types = [typ]
        elif isinstance(typ, list) and all(isinstance(t, str) for t in typ):
            allowed_types = list(typ)
        else:
            raise UnsupportedSchemaError("type must be a string or list of strings")

        if not any(_type_matches(instance, t) for t in allowed_types):
            issues.append(ValidationIssue(path, f"Expected type {allowed_types!r}"))
            return

    # Type-specific validation
    if isinstance(instance, dict):
        required = schema.get("required", [])
        if required:
            if not isinstance(required, list) or not all(isinstance(k, str) for k in required):
                raise UnsupportedSchemaError("required must be a list of strings")
            for key in required:
                if key not in instance:
                    issues.append(ValidationIssue(f"{path}/{key}" if path else key, "Missing required property"))

        properties = schema.get("properties", {})
        if properties and not isinstance(properties, dict):
            raise UnsupportedSchemaError("properties must be an object")

        additional = schema.get("additionalProperties", True)
        if not (isinstance(additional, (bool, dict))):
            raise UnsupportedSchemaError("additionalProperties must be a boolean or schema object")

        for key, value in instance.items():
            sub_path = f"{path}/{key}" if path else key
            if isinstance(properties, dict) and key in properties:
                _validate(value, properties[key], path=sub_path, issues=issues, root_schema=root_schema, ref_stack=ref_stack)
                continue

            if additional is False:
                issues.append(ValidationIssue(sub_path, "Additional property is not allowed"))
                continue
            if isinstance(additional, dict):
                _validate(value, additional, path=sub_path, issues=issues, root_schema=root_schema, ref_stack=ref_stack)

    if isinstance(instance, list):
        min_items = schema.get("minItems")
        max_items = schema.get("maxItems")
        if min_items is not None and (not _is_integer(min_items) or min_items < 0):
            raise UnsupportedSchemaError("minItems must be a non-negative integer")
        if max_items is not None and (not _is_integer(max_items) or max_items < 0):
            raise UnsupportedSchemaError("maxItems must be a non-negative integer")
        if min_items is not None and len(instance) < min_items:
            issues.append(ValidationIssue(path, f"Expected at least {min_items} items"))
        if max_items is not None and len(instance) > max_items:
            issues.append(ValidationIssue(path, f"Expected at most {max_items} items"))

        items = schema.get("items")
        if items is None:
            return
        if isinstance(items, list):
            # Tuple validation: schema per index. Ignore extra items unless additionalItems is false.
            for idx, sub_schema in enumerate(items):
                if idx >= len(instance):
                    break
                _validate(
                    instance[idx],
                    sub_schema,
                    path=f"{path}/{idx}" if path else str(idx),
                    issues=issues,
                    root_schema=root_schema,
                    ref_stack=ref_stack,
                )
            additional_items = schema.get("additionalItems", True)
            if additional_items is False and len(instance) > len(items):
                issues.append(ValidationIssue(path, "Additional array items are not allowed"))
            return
        if not isinstance(items, dict):
            raise UnsupportedSchemaError("items must be a schema object or list of schemas")

        for idx, value in enumerate(instance):
            _validate(
                value,
                items,
                path=f"{path}/{idx}" if path else str(idx),
                issues=issues,
                root_schema=root_schema,
                ref_stack=ref_stack,
            )

    if isinstance(instance, str):
        min_len = schema.get("minLength")
        max_len = schema.get("maxLength")
        if min_len is not None and (not _is_integer(min_len) or min_len < 0):
            raise UnsupportedSchemaError("minLength must be a non-negative integer")
        if max_len is not None and (not _is_integer(max_len) or max_len < 0):
            raise UnsupportedSchemaError("maxLength must be a non-negative integer")
        if min_len is not None and len(instance) < min_len:
            issues.append(ValidationIssue(path, f"Expected length >= {min_len}"))
        if max_len is not None and len(instance) > max_len:
            issues.append(ValidationIssue(path, f"Expected length <= {max_len}"))

        pattern = schema.get("pattern")
        if pattern is not None:
            if not isinstance(pattern, str):
                raise UnsupportedSchemaError("pattern must be a string")
            try:
                if re.search(pattern, instance) is None:
                    issues.append(ValidationIssue(path, "String does not match pattern"))
            except re.error as exc:
                raise UnsupportedSchemaError(f"Invalid regex pattern: {pattern!r}") from exc

    if _is_number(instance):
        minimum = schema.get("minimum")
        maximum = schema.get("maximum")
        exclusive_minimum = schema.get("exclusiveMinimum")
        exclusive_maximum = schema.get("exclusiveMaximum")

        if minimum is not None and not _is_number(minimum):
            raise UnsupportedSchemaError("minimum must be a number")
        if maximum is not None and not _is_number(maximum):
            raise UnsupportedSchemaError("maximum must be a number")
        if exclusive_minimum is not None and not _is_number(exclusive_minimum):
            raise UnsupportedSchemaError("exclusiveMinimum must be a number")
        if exclusive_maximum is not None and not _is_number(exclusive_maximum):
            raise UnsupportedSchemaError("exclusiveMaximum must be a number")

        if minimum is not None and instance < minimum:
            issues.append(ValidationIssue(path, f"Expected >= {minimum}"))
        if maximum is not None and instance > maximum:
            issues.append(ValidationIssue(path, f"Expected <= {maximum}"))
        if exclusive_minimum is not None and instance <= exclusive_minimum:
            issues.append(ValidationIssue(path, f"Expected > {exclusive_minimum}"))
        if exclusive_maximum is not None and instance >= exclusive_maximum:
            issues.append(ValidationIssue(path, f"Expected < {exclusive_maximum}"))
