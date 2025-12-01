import urllib.parse
from typing import Any, Dict, Optional, List

class WAFEvasionMiddleware:
    """
    Adaptive WAF Evasion Middleware.

    This middleware intercepts failed requests (403/406) and attempts to retry them
    using semantic equivalent payloads to bypass WAFs.
    """

    def __init__(self):
        self.waf_profile = {
            "blocked_chars": set(),
            "blocked_keywords": set(),
            "successful_techniques": []
        }

    def process_response(self, request: Dict[str, Any], response: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Check if response indicates a WAF block. If so, return a modified request payload (new mutation).
        If not blocked or no evasion possible, return None.
        """
        status_code = response.get("status_code", 0)

        # Detect WAF block
        if status_code in [403, 406] or "waf" in str(response.get("body", "")).lower():
            # For simplicity, we only try one mutation per block to avoid infinite loops in this basic implementation
            # In a real agent, we would check if this request was already a mutation.
            if request.get("headers", {}).get("X-WAF-Evasion-Attempt"):
                return None

            return self._generate_evasion_mutation(request)

        return None

    def _generate_evasion_mutation(self, request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Generate a mutated request to evade WAF.
        """
        mutated_request = request.copy()
        headers = mutated_request.get("headers", {}).copy()
        headers["X-WAF-Evasion-Attempt"] = "true"
        mutated_request["headers"] = headers

        # Strategy 1: Header Manipulation (User-Agent rotation)
        headers["User-Agent"] = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"

        # Strategy 2: URL Encoding (if applicable)
        if "url" in mutated_request:
            # Simple double encoding simulation or specific char encoding
            # For this MVP, we just append a cache buster or harmless param to change signature
            if "?" in mutated_request["url"]:
                mutated_request["url"] += "&waf_bypass=1"
            else:
                mutated_request["url"] += "?waf_bypass=1"

        # Strategy 3: Whitespace Polymorphism (concept only as we don't have SQL parser here)
        # If body is present and looks like SQL, we could replace spaces with comments.

        return mutated_request

    def update_profile(self, payload: str, was_blocked: bool):
        """
        Update the WAF profile based on success/failure of payloads.
        """
        if was_blocked:
             # Logic to analyze what was blocked
             pass
        else:
            if payload:
                 self.waf_profile["successful_techniques"].append(payload)

# Singleton instance
waf_middleware = WAFEvasionMiddleware()
