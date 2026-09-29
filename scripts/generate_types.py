"""Generate frontend analysis contracts from the authoritative Pydantic schemas."""

from pathlib import Path

from firmwarelens.schemas import AIAnswer, AnalysisResult, ScanOptions, TriageUpdate


def ts(schema):
    if "$ref" in schema:
        return schema["$ref"].split("/")[-1]
    if "enum" in schema:
        import json

        return " | ".join(json.dumps(value) for value in schema["enum"])
    if "anyOf" in schema:
        return " | ".join(ts(item) for item in schema["anyOf"])
    kind = schema.get("type")
    if kind == "array":
        return f"({ts(schema.get('items', {}))})[]"
    if kind == "object":
        props = schema.get("properties", {})
        if props:
            return (
                "{\n"
                + "\n".join(
                    f"  {key}{'' if key in schema.get('required', []) else '?'}: {ts(value)};"
                    for key, value in props.items()
                )
                + "\n}"
            )
        extra = schema.get("additionalProperties", {})
        return f"Record<string, {ts(extra) if isinstance(extra, dict) else 'unknown'}>"
    return {
        "string": "string",
        "integer": "number",
        "number": "number",
        "boolean": "boolean",
        "null": "null",
    }.get(kind, "unknown")


schemas = {}
for model in (AnalysisResult, ScanOptions, AIAnswer, TriageUpdate):
    schema = model.model_json_schema()
    schemas.update(schema.pop("$defs", {}))
    schemas[model.__name__] = schema
destination = Path("frontend/src/generated.ts")
destination.parent.mkdir(parents=True, exist_ok=True)
destination.write_text(
    "// Generated from Pydantic. Run scripts/generate_types.py; do not edit.\n"
    + "\n".join(f"export type {name} = {ts(schema)};\n" for name, schema in sorted(schemas.items()))
)
