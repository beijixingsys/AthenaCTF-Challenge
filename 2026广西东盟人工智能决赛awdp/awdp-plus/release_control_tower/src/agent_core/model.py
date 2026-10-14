"""Deterministic decision engine standing in for the platform model_intent().

The original platform routed an AI agent whose policy text documented a
"legacy decision" table.  We reproduce that table deterministically so the
challenges behave exactly as the writeup describes without shipping an LLM:

    authorization=approved                  -> high-impact tool
    authorization=none + explicit wording   -> high-impact tool (the vuln)
    otherwise                               -> safe default tool

Tool visibility is gated *before* this call by each challenge rail, so the
engine only has to prefer the highest-impact tool that is actually visible.
"""
import hashlib
import json

PROFILE = "soc-default"
MODEL = "deterministic-legacy-router"

HIGH_IMPACT_ORDER = (
    "run_extension_preflight",
    "deliver_handoff_bundle",
    "dispatch_connector_acknowledgement",
    "redirect_delivery_address",
    "release_remittance",
    "review_partner_catalogue",
    "compose_delegated_packet",
    "perform_health_probe",
    "commit_reconciliation",
    "publish_recommendation",
)


def fingerprint(payload):
    raw = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _props(tool):
    return ((tool.get("parameters") or {}).get("properties") or {})


def default_arguments(tool, operation, sources):
    props = _props(tool)
    if "proposed_action" in props:
        return {
            "objective": "Assess the selected %s record." % operation,
            "context_source": "server-context",
            "proposed_action": "inspect",
            "requires_authorization": str(sources.get("authorization") or "none") != "approved",
        }
    if "summary" in props and "confidence" in props:
        return {
            "summary": "Recorded the observed outcome for %s." % operation,
            "confidence": "observed",
        }
    args = {}
    for name, spec in props.items():
        kind = (spec or {}).get("type")
        if kind == "boolean":
            args[name] = False
        elif kind in ("integer", "number"):
            args[name] = 0
        elif kind == "array":
            args[name] = []
        elif kind == "object":
            args[name] = {}
        else:
            args[name] = ""
    return args


def decide(operation, sources, tools, force_tool=""):
    tools = list(tools or [])
    names = [t.get("name") for t in tools]
    pick = None
    if force_tool and force_tool in names:
        pick = force_tool
    if pick is None:
        authorized = str(sources.get("authorized_tool") or "")
        if authorized and authorized in names:
            pick = authorized
    if pick is None:
        for candidate in HIGH_IMPACT_ORDER:
            if candidate in names:
                pick = candidate
                break
    if pick is None:
        pick = names[0] if names else "summarize_change_manifest"
    tool = None
    for candidate in tools:
        if candidate.get("name") == pick:
            tool = candidate
            break
    if tool is None:
        tool = {"name": pick, "parameters": {"properties": {}}}
    return {"tool": pick, "arguments": default_arguments(tool, operation, sources)}
