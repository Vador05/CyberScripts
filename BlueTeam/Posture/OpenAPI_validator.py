#!/usr/bin/env python3
"""
openapi_probe.py

Walk an OpenAPI 3.x schema, generate basic sample inputs, execute calls,
and record:
- status code
- whether the status code is documented
- response time
- content-type match
- JSON parse success
- response schema validation result
- an overall "quality_score"

Safety:
- By default, only GET/HEAD/OPTIONS are executed.
- Use --allow-write to include POST/PUT/PATCH/DELETE.

Example:
    python openapi_probe.py \
        --spec openapi.yaml \
        --base-url https://api.example.com \
        --token YOUR_BEARER_TOKEN \
        --output report.json

"""
import argparse
import copy
import json
import os
import random
import re
import sys
import time
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse
import requests
import yaml

try:
    from jsonschema import validate as jsonschema_validate
    from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
    JSONSCHEMA_AVAILABLE = True
except Exception:
    JSONSCHEMA_AVAILABLE = False


SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
ALL_HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}

DEFAULT_HEADERS = {
    "Accept": "application/json",
    "User-Agent": "openapi-probe/1.0"
}


def load_spec(path_or_url: str) -> Dict[str, Any]:
    if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
        resp = requests.get(path_or_url, timeout=30)
        resp.raise_for_status()
        text = resp.text
    else:
        with open(path_or_url, "r", encoding="utf-8") as f:
            text = f.read()

    try:
        return yaml.safe_load(text)
    except Exception as e:
        raise RuntimeError(f"Failed to parse spec as YAML/JSON: {e}")


def deep_merge(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(a)
    for k, v in b.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def resolve_json_pointer(doc: Dict[str, Any], ref: str) -> Any:
    """
    Supports local refs like: #/components/schemas/MyType
    """
    if not ref.startswith("#/"):
        raise ValueError(f"Only local $ref values are supported in this script: {ref}")
    parts = ref[2:].split("/")
    node = doc
    for part in parts:
        part = part.replace("~1", "/").replace("~0", "~")
        node = node[part]
    return node


def resolve_refs(obj: Any, doc: Dict[str, Any], seen: Optional[set] = None) -> Any:
    """
    Recursively resolve local $ref entries.
    """
    if seen is None:
        seen = set()

    if isinstance(obj, dict):
        if "$ref" in obj:
            ref = obj["$ref"]
            if ref in seen:
                return obj  # avoid recursion loops
            seen.add(ref)
            resolved = resolve_json_pointer(doc, ref)
            merged = copy.deepcopy(resolved)

            # if sibling keys exist alongside $ref, merge them in
            sibling_keys = {k: v for k, v in obj.items() if k != "$ref"}
            if sibling_keys:
                merged = deep_merge(merged, sibling_keys)

            return resolve_refs(merged, doc, seen)

        return {k: resolve_refs(v, doc, seen) for k, v in obj.items()}

    if isinstance(obj, list):
        return [resolve_refs(x, doc, seen) for x in obj]

    return obj

def normalize_base_url(url: Optional[str]) -> Optional[str]:
    if not url:
        return None
    url = url.strip()
    if not url:
        return None

    parsed = urlparse(url)
    if not parsed.scheme:
        url = "https://" + url

    return url.rstrip("/")


def pick_server_url(spec: Dict[str, Any], override: Optional[str]) -> Optional[str]:
    if override:
        return normalize_base_url(override)

    servers = spec.get("servers", [])
    if servers:
        url = servers[0].get("url")
        if url:
            return normalize_base_url(url)

    return None

def sample_string(fmt: Optional[str] = None, enum: Optional[List[Any]] = None) -> str:
    if enum:
        return str(enum[0])
    samples = {
        "uuid": "123e4567-e89b-12d3-a456-426614174000",
        "date": "2026-01-01",
        "date-time": "2026-01-01T12:00:00Z",
        "email": "test@example.com",
        "hostname": "example.local",
        "ipv4": "127.0.0.1",
        "ipv6": "2001:db8::1",
        "uri": "https://example.com/resource",
        "uri-reference": "/resource/123",
        "binary": "ZGF0YQ==",
        "byte": "ZGF0YQ==",
        "password": "P@ssw0rd123"
    }
    return samples.get(fmt, "sample-string")


def generate_sample_from_schema(schema: Dict[str, Any], depth: int = 0) -> Any:
    """
    Generate a basic sample payload from a JSON Schema-ish OpenAPI schema.
    Intentionally conservative and simple.
    """
    if depth > 5:
        return None

    if not schema:
        return None

    # Prefer example/default/enum
    if "example" in schema:
        return schema["example"]
    if "default" in schema:
        return schema["default"]
    if "enum" in schema and schema["enum"]:
        return schema["enum"][0]

    # Handle composition
    if "oneOf" in schema and schema["oneOf"]:
        return generate_sample_from_schema(schema["oneOf"][0], depth + 1)
    if "anyOf" in schema and schema["anyOf"]:
        return generate_sample_from_schema(schema["anyOf"][0], depth + 1)
    if "allOf" in schema and schema["allOf"]:
        merged = {}
        for part in schema["allOf"]:
            if isinstance(part, dict):
                merged = deep_merge(merged, part)
        return generate_sample_from_schema(merged, depth + 1)

    schema_type = schema.get("type")

    # Infer object type if properties exist
    if not schema_type and "properties" in schema:
        schema_type = "object"

    # Infer array type if items exist
    if not schema_type and "items" in schema:
        schema_type = "array"

    if schema_type == "string":
        return sample_string(schema.get("format"), schema.get("enum"))

    if schema_type == "integer":
        if "minimum" in schema:
            return int(schema["minimum"])
        return 1

    if schema_type == "number":
        if "minimum" in schema:
            return float(schema["minimum"])
        return 1.0

    if schema_type == "boolean":
        return True

    if schema_type == "array":
        item_schema = schema.get("items", {})
        return [generate_sample_from_schema(item_schema, depth + 1)]

    if schema_type == "object":
        result = {}
        props = schema.get("properties", {})
        required = set(schema.get("required", []))

        # Prefer required properties; if none are required, include up to 3 props
        selected_props = list(required) if required else list(props.keys())[:3]

        for prop_name in selected_props:
            prop_schema = props.get(prop_name, {})
            result[prop_name] = generate_sample_from_schema(prop_schema, depth + 1)

        # If object has no properties, return empty object
        return result

    # fallback
    return "sample"


def combine_parameters(path_item: Dict[str, Any], operation: Dict[str, Any]) -> List[Dict[str, Any]]:
    params = []
    seen = set()

    for src in [path_item.get("parameters", []), operation.get("parameters", [])]:
        for p in src:
            key = (p.get("name"), p.get("in"))
            if key not in seen:
                params.append(p)
                seen.add(key)

    return params


def build_inputs(
    spec: Dict[str, Any],
    path_template: str,
    method: str,
    path_item: Dict[str, Any],
    operation: Dict[str, Any]
) -> Dict[str, Any]:
    resolved_op = resolve_refs(operation, spec)
    resolved_path_item = resolve_refs(path_item, spec)

    params = combine_parameters(resolved_path_item, resolved_op)

    path_params = {}
    query_params = {}
    header_params = {}
    cookie_params = {}

    for p in params:
        name = p.get("name")
        location = p.get("in")
        schema = p.get("schema", {})
        value = generate_sample_from_schema(schema)

        # If parameter is required and fallback produced None, give a generic value
        if value is None:
            value = "sample"

        if location == "path":
            path_params[name] = value
        elif location == "query":
            query_params[name] = value
        elif location == "header":
            header_params[name] = str(value)
        elif location == "cookie":
            cookie_params[name] = str(value)

    request_body = None
    request_content_type = None

    if "requestBody" in resolved_op:
        req_body = resolved_op["requestBody"]
        content = req_body.get("content", {})

        # Prefer JSON, then form, then multipart, then first available
        preferred = [
            "application/json",
            "application/x-www-form-urlencoded",
            "multipart/form-data"
        ]
        content_type = next((ct for ct in preferred if ct in content), None)
        if not content_type and content:
            content_type = next(iter(content.keys()))

        if content_type:
            media = content[content_type]
            schema = media.get("schema", {})
            request_body = generate_sample_from_schema(schema)
            request_content_type = content_type

    # Build final path by replacing template params
    final_path = path_template
    for name, value in path_params.items():
        final_path = final_path.replace("{" + name + "}", str(value))

    return {
        "path": final_path,
        "path_params": path_params,
        "query_params": query_params,
        "header_params": header_params,
        "cookie_params": cookie_params,
        "request_body": request_body,
        "request_content_type": request_content_type
    }


def expected_response_def(operation: Dict[str, Any], status_code: int) -> Optional[Dict[str, Any]]:
    responses = operation.get("responses", {})
    code_str = str(status_code)

    if code_str in responses:
        return responses[code_str]

    # Handle wildcard families like 2XX, 4XX, etc.
    family = f"{code_str[0]}XX"
    if family in responses:
        return responses[family]

    if "default" in responses:
        return responses["default"]

    return None


def status_is_documented(operation: Dict[str, Any], status_code: int) -> bool:
    return expected_response_def(operation, status_code) is not None


def pick_expected_content_types(resp_def: Dict[str, Any]) -> List[str]:
    if not resp_def:
        return []
    content = resp_def.get("content", {})
    return list(content.keys())


def content_type_matches(actual: Optional[str], expected_content_types: List[str]) -> bool:
    if not expected_content_types:
        return True  # nothing documented
    if not actual:
        return False

    actual_main = actual.split(";")[0].strip().lower()
    expected_main = [x.split(";")[0].strip().lower() for x in expected_content_types]
    return actual_main in expected_main


def convert_openapi_schema_to_jsonschema(schema: Dict[str, Any]) -> Dict[str, Any]:
    """
    Very lightweight conversion / cleanup for validating response JSON
    with jsonschema. Good enough for many common cases.
    """
    schema = copy.deepcopy(schema)

    def _clean(node: Any) -> Any:
        if isinstance(node, dict):
            node.pop("nullable", None)  # OpenAPI extension, not JSON Schema draft as-is
            # Remove readOnly/writeOnly if present
            node.pop("readOnly", None)
            node.pop("writeOnly", None)
            for k, v in list(node.items()):
                node[k] = _clean(v)
            return node
        if isinstance(node, list):
            return [_clean(x) for x in node]
        return node

    return _clean(schema)


def validate_response_schema(
    spec: Dict[str, Any],
    operation: Dict[str, Any],
    status_code: int,
    actual_content_type: Optional[str],
    response_body_text: str
) -> Tuple[Optional[bool], Optional[str]]:
    """
    Returns:
        (is_valid, error_message)
    """
    if not JSONSCHEMA_AVAILABLE:
        return None, "jsonschema package not installed"

    resp_def = expected_response_def(operation, status_code)
    if not resp_def:
        return None, "No documented response for this status"

    content = resp_def.get("content", {})
    if not content:
        return None, "No response content schema documented"

    actual_main = (actual_content_type or "").split(";")[0].strip().lower()
    if actual_main in content:
        media = content[actual_main]
    elif "application/json" in content:
        media = content["application/json"]
    else:
        first_ct = next(iter(content.keys()))
        media = content[first_ct]

    schema = media.get("schema")
    if not schema:
        return None, "No schema found for documented response content"

    try:
        payload = json.loads(response_body_text)
    except Exception as e:
        return False, f"Response is not valid JSON: {e}"

    schema = resolve_refs(schema, spec)
    schema = convert_openapi_schema_to_jsonschema(schema)

    try:
        jsonschema_validate(instance=payload, schema=schema)
        return True, None
    except JsonSchemaValidationError as e:
        return False, str(e)
    except Exception as e:
        return None, f"Validation could not be completed: {e}"


def compute_quality_score(
    documented_status: bool,
    content_type_ok: bool,
    json_parse_ok: Optional[bool],
    schema_valid: Optional[bool]
) -> int:
    """
    Simple 0-100 quality score.
    """
    score = 0
    if documented_status:
        score += 35
    if content_type_ok:
        score += 20
    if json_parse_ok is True:
        score += 15
    elif json_parse_ok is None:
        score += 5  # neutral if not JSON / not applicable
    if schema_valid is True:
        score += 30
    elif schema_valid is None:
        score += 10  # partial credit if validation unavailable/not applicable
    return min(score, 100)


def send_request(
    method: str,
    url: str,
    timeout: int,
    headers: Dict[str, str],
    query_params: Dict[str, Any],
    cookie_params: Dict[str, Any],
    request_body: Any,
    request_content_type: Optional[str]
) -> requests.Response:
    kwargs: Dict[str, Any] = {
        "method": method,
        "url": url,
        "headers": headers,
        "params": query_params,
        "cookies": cookie_params,
        "timeout": timeout,
    }

    if request_body is not None and method in {"POST", "PUT", "PATCH", "DELETE"}:
        if request_content_type == "application/json":
            kwargs["json"] = request_body
        elif request_content_type == "application/x-www-form-urlencoded":
            kwargs["data"] = request_body
        elif request_content_type == "multipart/form-data":
            # simplistic multipart handling: text fields only
            kwargs["files"] = {
                k: (None, str(v)) for k, v in (request_body or {}).items()
            }
        else:
            # fallback
            kwargs["json"] = request_body

    return requests.request(**kwargs)


def main():
    parser = argparse.ArgumentParser(description="Probe an OpenAPI spec and record response quality")
    parser.add_argument("--spec", required=True, help="Path or URL to OpenAPI YAML/JSON")
    parser.add_argument("--base-url", help="Override the server URL from the spec")
    parser.add_argument("--token", help="Bearer token")
    parser.add_argument("--api-key", help="API key value")
    parser.add_argument("--api-key-header", default="X-API-Key", help="Header name for API key")
    parser.add_argument("--timeout", type=int, default=20, help="Per-request timeout in seconds")
    parser.add_argument("--output", default="openapi_report.json", help="Output report JSON file")
    parser.add_argument("--allow-write", action="store_true", help="Allow POST/PUT/PATCH/DELETE")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    args = parser.parse_args()

    requests.packages.urllib3.disable_warnings()  # only relevant if --insecure

    spec = load_spec(args.spec)
    base_url = pick_server_url(spec, args.base_url)

    if not base_url:
        print("ERROR: No server URL found in spec and --base-url was not provided.", file=sys.stderr)
        sys.exit(2)

    session_headers = dict(DEFAULT_HEADERS)
    if args.token:
        session_headers["Authorization"] = f"Bearer {args.token}"
    if args.api_key:
        session_headers[args.api_key_header] = args.api_key

    results = []
    started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    paths = spec.get("paths", {})
    if not paths:
        print("ERROR: Spec has no paths", file=sys.stderr)
        sys.exit(2)

    for path_template, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue

        for method, operation in path_item.items():
            method_upper = method.upper()
            if method_upper not in ALL_HTTP_METHODS:
                continue

            if not args.allow_write and method_upper not in SAFE_METHODS:
                # skip write methods in safe mode
                continue

            resolved_op = resolve_refs(operation, spec)

            op_id = resolved_op.get("operationId", f"{method_upper} {path_template}")
            summary = resolved_op.get("summary", "")

            try:
                inputs = build_inputs(spec, path_template, method_upper, path_item, operation)
                url = base_url + inputs["path"]

                headers = dict(session_headers)
                headers.update(inputs["header_params"])

                t0 = time.perf_counter()
                resp = requests.request(
                    method=method_upper,
                    url=url,
                    headers=headers,
                    params=inputs["query_params"],
                    cookies=inputs["cookie_params"],
                    timeout=args.timeout,
                    verify=not args.insecure,
                    json=inputs["request_body"] if inputs["request_content_type"] == "application/json" and method_upper in {"POST", "PUT", "PATCH", "DELETE"} else None,
                    data=inputs["request_body"] if inputs["request_content_type"] == "application/x-www-form-urlencoded" and method_upper in {"POST", "PUT", "PATCH", "DELETE"} else None,
                    files={k: (None, str(v)) for k, v in (inputs["request_body"] or {}).items()} if inputs["request_content_type"] == "multipart/form-data" and method_upper in {"POST", "PUT", "PATCH", "DELETE"} else None,
                )
                elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)

                actual_ct = resp.headers.get("Content-Type")
                documented = status_is_documented(resolved_op, resp.status_code)
                expected_def = expected_response_def(resolved_op, resp.status_code)
                expected_cts = pick_expected_content_types(expected_def) if expected_def else []
                ct_ok = content_type_matches(actual_ct, expected_cts)

                json_parse_ok = None
                try:
                    if actual_ct and "json" in actual_ct.lower():
                        resp.json()
                        json_parse_ok = True
                except Exception:
                    json_parse_ok = False

                schema_valid, schema_error = validate_response_schema(
                    spec,
                    resolved_op,
                    resp.status_code,
                    actual_ct,
                    resp.text
                )

                quality_score = compute_quality_score(
                    documented_status=documented,
                    content_type_ok=ct_ok,
                    json_parse_ok=json_parse_ok,
                    schema_valid=schema_valid
                )

                results.append({
                    "operationId": op_id,
                    "summary": summary,
                    "method": method_upper,
                    "path_template": path_template,
                    "resolved_path": inputs["path"],
                    "url": url,
                    "inputs": {
                        "path_params": inputs["path_params"],
                        "query_params": inputs["query_params"],
                        "header_params": {k: ("***" if k.lower() == "authorization" else v) for k, v in inputs["header_params"].items()},
                        "cookie_params": inputs["cookie_params"],
                        "request_content_type": inputs["request_content_type"],
                        "request_body": inputs["request_body"],
                    },
                    "response": {
                        "status_code": resp.status_code,
                        "elapsed_ms": elapsed_ms,
                        "content_type": actual_ct,
                        "content_length": len(resp.content),
                        "documented_status": documented,
                        "expected_content_types": expected_cts,
                        "content_type_match": ct_ok,
                        "json_parse_ok": json_parse_ok,
                        "schema_valid": schema_valid,
                        "schema_error": schema_error,
                        "quality_score": quality_score,
                        "body_preview": resp.text[:1000],
                    }
                })

                print(f"[OK] {method_upper} {path_template} -> {resp.status_code} ({elapsed_ms} ms)")

            except Exception as e:
                results.append({
                    "operationId": op_id,
                    "summary": summary,
                    "method": method_upper,
                    "path_template": path_template,
                    "resolved_path": None,
                    "url": None,
                    "inputs": None,
                    "response": None,
                    "error": str(e)
                })
                print(f"[ERR] {method_upper} {path_template} -> {e}", file=sys.stderr)

    finished_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    report = {
        "started_at": started_at,
        "finished_at": finished_at,
        "base_url": base_url,
        "safe_mode": not args.allow_write,
        "jsonschema_available": JSONSCHEMA_AVAILABLE,
        "results": results
    }

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"\nReport written to: {args.output}")

    # basic summary
    total = len(results)
    successful_calls = sum(1 for r in results if r.get("response") is not None)
    avg_quality = None
    quality_values = [r["response"]["quality_score"] for r in results if r.get("response")]
    if quality_values:
        avg_quality = round(sum(quality_values) / len(quality_values), 2)

    print(f"Total operations tested: {total}")
    print(f"Successful calls: {successful_calls}")
    print(f"Average quality score: {avg_quality if avg_quality is not None else 'N/A'}")
    
    status_counts = {}
    for r in results:
        resp = r.get("response")
        if resp and "status_code" in resp:
            code = resp["status_code"]
            status_counts[code] = status_counts.get(code, 0) + 1

    print(f"Status counts: {status_counts}")

    good_2xx = sum(1 for r in results if r.get("response") and 200 <= r["response"]["status_code"] < 300)
    not_found_404 = sum(1 for r in results if r.get("response") and r["response"]["status_code"] == 404)
    unauth_401 = sum(1 for r in results if r.get("response") and r["response"]["status_code"] == 401)
    forbidden_403 = sum(1 for r in results if r.get("response") and r["response"]["status_code"] == 403)

    print(f"2xx responses: {good_2xx}")
    print(f"404 responses: {not_found_404}")
    print(f"401 responses: {unauth_401}")
    print(f"403 responses: {forbidden_403}")



if __name__ == "__main__":
    main()