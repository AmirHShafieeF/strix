import esprima
import json
from typing import Any, List, Dict
from strix.tools.registry import register_tool

@register_tool
def analyze_js_ast(js_code: str) -> str:
    """
    Analyzes JavaScript code using AST parsing to find interesting literals (strings, numbers)
    and potential API endpoints or secrets.
    """
    try:
        tree = esprima.parseScript(js_code, options={'tolerant': True, 'loc': True})
    except Exception as e:
        return f"Error parsing JS: {e}"

    findings = {
        "literals": set(),
        "identifiers": set(),
        "potential_urls": set(),
        "potential_secrets": set(),
    }

    def traverse(node):
        if not node:
            return

        # Check for literals
        if node.type == 'Literal':
            value = node.value
            if isinstance(value, str):
                if len(value) > 3:
                    findings["literals"].add(value)
                if value.startswith(("http", "/api", "/v1")):
                    findings["potential_urls"].add(value)
                # Lower threshold for secrets for testing purposes
                if len(value) > 10 and any(k in value.lower() for k in ["key", "token", "secret", "password", "sk_", "pk_"]):
                     findings["potential_secrets"].add(value) # Heuristic

        # Check for identifiers
        if node.type == 'Identifier':
            findings["identifiers"].add(node.name)

        # Recursion
        for key, value in node.__dict__.items():
            if key in ['type', 'loc', 'range']: continue
            if isinstance(value, list):
                for item in value:
                    if hasattr(item, 'type'):
                        traverse(item)
            elif hasattr(value, 'type'):
                traverse(value)

    traverse(tree)

    # Format output
    report = []
    if findings["potential_urls"]:
        report.append("Potential URLs/Endpoints:")
        report.extend(f"- {u}" for u in sorted(findings["potential_urls"]))
        report.append("")

    if findings["potential_secrets"]:
        report.append("Potential Secrets (High Entropy/Keywords):")
        report.extend(f"- {s}" for s in sorted(findings["potential_secrets"]))
        report.append("")

    report.append(f"Found {len(findings['literals'])} string literals and {len(findings['identifiers'])} identifiers.")

    return "\n".join(report) if report else "No significant findings from AST analysis."
