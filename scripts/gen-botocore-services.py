#!/usr/bin/env python3
"""Regenerates data/botocore-services.json.

Usage: pip install botocore && python3 scripts/gen-botocore-services.py <names_data.hcl>

names_data.hcl comes from hashicorp/terraform-provider-aws (names/data/). It names one
cheap read call per service. That call is the service probe when it has a fixed URI;
otherwise the first List or Describe call that has one is used.
"""

import json
import re
import sys
from pathlib import Path

import botocore
import botocore.session

PROTOCOLS = {"json", "query", "ec2", "rest-json", "rest-xml"}
READ = ("List", "Describe", "Get")


def probe_ops(names_data: str) -> dict[str, str]:
    ops = {}
    for block in re.split(r'^service "', names_data, flags=re.M)[1:]:
        sid = re.search(r'^\s*id\s*=\s*"([^"]+)"', block, re.M)
        op = re.search(r'endpoint_api_call\s*=\s*"([^"]+)"', block)
        if sid and op:
            ops[sid.group(1)] = op.group(1)
    return ops


def usable(model, protocol, op_name):
    # A missing required parameter only makes the service answer with a validation
    # error, which still proves it is there. Path parameters cannot be left out.
    op = model.operation_model(op_name)
    uri = op.http.get("requestUri", "/")
    method = op.http.get("method", "POST")
    if "{" in uri or (protocol.startswith("rest") and method != "GET"):
        return None
    return {"op": op_name, "method": method, "uri": uri}


def probe(model, protocol, preferred):
    """The provider's named call if it is a read call and usable, else the first usable
    List or Describe call. Live mode is read-only, so no other call is ever a probe."""
    names = [preferred] if preferred in model.operation_names and preferred.startswith(READ) else []
    names += sorted(n for n in model.operation_names if n.startswith(("List", "Describe")))
    return next((p for n in names if (p := usable(model, protocol, n)) is not None), None)


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    ops = probe_ops(Path(sys.argv[1]).read_text(encoding="utf-8"))
    session = botocore.session.get_session()
    services = []
    for name in session.get_available_services():
        model = session.get_service_model(name)
        meta = model.metadata
        protocol = next((p for p in meta.get("protocols", [meta["protocol"]]) if p in PROTOCOLS), None)
        if protocol is None:
            continue
        entry = {
            "service_id": meta["serviceId"],
            "endpoint_prefix": meta["endpointPrefix"],
            "signing_name": meta.get("signingName", meta["endpointPrefix"]),
            "protocol": protocol,
            "api_version": meta["apiVersion"],
        }
        if protocol == "json":
            entry["target_prefix"] = meta["targetPrefix"]
            entry["json_version"] = meta.get("jsonVersion", "1.0")
        if (p := probe(model, protocol, ops.get(meta["serviceId"], ""))) is not None:
            entry["probe"] = p
        services.append(entry)
    services.sort(key=lambda e: e["service_id"])
    out = {"botocore_version": botocore.__version__, "services": services}
    path = Path(__file__).resolve().parent.parent / "data" / "botocore-services.json"
    path.write_text(json.dumps(out, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"{len(services)} services, {sum('probe' in s for s in services)} probes -> {path}")


if __name__ == "__main__":
    main()
