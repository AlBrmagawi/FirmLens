"""Validate generated SBOM and SARIF against downloaded official schemas."""

import hashlib
import json
import urllib.request
from pathlib import Path

import jsonschema
from referencing import Registry, Resource

directory = Path("tests/schemas")
directory.mkdir(parents=True, exist_ok=True)
urls = {
    "bom-1.7.schema.json": "https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.7.schema.json",
    "spdx.schema.json": "https://raw.githubusercontent.com/CycloneDX/specification/master/schema/spdx.schema.json",
    "jsf-0.82.schema.json": "https://raw.githubusercontent.com/CycloneDX/specification/master/schema/jsf-0.82.schema.json",
    "cryptography-defs.schema.json": "https://raw.githubusercontent.com/CycloneDX/specification/master/schema/cryptography-defs.schema.json",
    "sarif-schema-2.1.0.json": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
}
resources = []
provenance = {}
for name, url in urls.items():
    path = directory / name
    if not path.exists():
        with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310
            payload = response.read(2000000)
        json.loads(payload)
        path.write_bytes(payload)
    schema = json.loads(path.read_bytes())
    resource = Resource.from_contents(schema)
    for uri in (
        url,
        schema.get("$id", url),
        "http://cyclonedx.org/schema/" + name,
        "https://cyclonedx.org/schema/" + name,
    ):
        resources.append((uri, resource))
    provenance[name] = {"source": url, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
(directory / "provenance.json").write_text(json.dumps(provenance, indent=2))
registry = Registry().with_resources(resources)
for release in ("lab", "revised"):
    for extension, schema_file in [
        ("cdx.json", "bom-1.7.schema.json"),
        ("sarif.json", "sarif-schema-2.1.0.json"),
    ]:
        instance = json.loads(Path(f"exports/{release}.{extension}").read_text())
        schema = json.loads((directory / schema_file).read_text())
        validator = jsonschema.validators.validator_for(schema)(schema, registry=registry)
        validator.validate(instance)
        print(f"Validated {release}.{extension}")
