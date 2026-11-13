#!/usr/bin/env python3
"""Checks data/esc-guide-rules.json against the resource schemas.

Usage: python3 scripts/check-rules.py <CloudformationSchema.zip> <tf-schema.json>

CloudformationSchema.zip is the CloudFormation registry schema bundle
(https://schema.cloudformation.us-east-1.amazonaws.com/CloudformationSchema.zip).
tf-schema.json is `terraform providers schema -json` for the aws and awscc providers.

Every type must exist, every condition path must resolve on at least one of the
rule's types, and every type of a rule with conditions must be reached by one.
"""

import json
import sys
import zipfile
from pathlib import Path

RULES = Path(__file__).resolve().parent.parent / "data" / "esc-guide-rules.json"


def cfn_schemas(zip_path):
    out = {}
    with zipfile.ZipFile(zip_path) as z:
        for name in z.namelist():
            s = json.loads(z.read(name))
            out[s["typeName"]] = s
    return out


def tf_schemas(path):
    out = {}
    for p in json.load(open(path, encoding="utf-8"))["provider_schemas"].values():
        out.update(p["resource_schemas"])
    return out


def cfn_node(schema, path):
    """The schema node at `path`, `{}` inside a free-form object, or None."""
    defs = schema.get("definitions", {})

    def deref(node):
        while "$ref" in node:
            node = defs.get(node["$ref"].split("/")[-1], {})
        if node.get("type") == "array" or "items" in node:
            return deref(node.get("items", {}))
        return node

    node = {"properties": schema.get("properties", {})}
    for key in path.split("."):
        node = deref(node)
        props = node.get("properties")
        if props is None:
            # Free-form objects (maps, JSON) accept any key.
            return {} if node.get("type") == "object" else None
        if key not in props:
            return None
        node = props[key]
    return deref(node)


def cfn_resolves(schema, path, cond=None):
    node = cfn_node(schema, path)
    if node is None:
        return False
    enum = [str(e).lower() for e in node.get("enum", [])]
    if not enum or not cond:
        return True
    if "equals" in cond:
        return cond["equals"].lower() in enum
    if "prefix" in cond:
        return any(e.startswith(cond["prefix"].lower()) for e in enum)
    if "not_in" in cond:
        return all(v.lower() in enum for v in cond["not_in"])
    return True


def tf_resolves(schema, path, cond=None):
    block = schema["block"]
    keys = path.split(".")
    for i, key in enumerate(keys):
        if key in block.get("attributes", {}):
            attr = block["attributes"][key]
            rest = keys[i + 1 :]
            if not rest:
                return True
            if "nested_type" in attr:
                return tf_resolves({"block": attr["nested_type"]}, ".".join(rest))
            t = attr["type"]
            while isinstance(t, list) and t[0] in ("list", "set"):
                t = t[1]
            if isinstance(t, list) and t[0] == "map":
                return len(rest) == 1
            if isinstance(t, list) and t[0] == "object":
                return rest[0] in t[1] and len(rest) == 1
            return False
        if key in block.get("block_types", {}):
            block = block["block_types"][key]["block"]
            continue
        return False
    return True


def leaves(conds):
    for c in conds:
        if c.get("all"):
            yield c["all"]
        else:
            yield [c]


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    cfn, tf = cfn_schemas(sys.argv[1]), tf_schemas(sys.argv[2])
    errors = []
    for r in json.load(open(RULES, encoding="utf-8"))["rules"]:
        known = {}
        for t in r["types"]:
            if t.startswith("AWS::"):
                if t in cfn:
                    known[t] = lambda p, v, s=cfn[t]: cfn_resolves(s, p, v)
                else:
                    errors.append(f"{r['id']}: unknown CloudFormation type {t}")
            elif t in tf:
                known[t] = lambda p, v, s=tf[t]: tf_resolves(s, p, v)
            else:
                errors.append(f"{r['id']}: unknown Terraform type {t}")
        reached = set()
        for group in leaves(r.get("when", [])):
            hits = [
                t for t, ok in known.items() if all(ok(c["path"], c) for c in group)
            ]
            if not hits:
                errors.append(f"{r['id']}: {[c['path'] for c in group]} resolves on none of its types")
            reached.update(hits)
        if r.get("when"):
            for t in sorted(set(known) - reached):
                errors.append(f"{r['id']}: no condition reaches {t}")
    for e in errors:
        print(e)
    print(f"{len(errors)} problems")
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
