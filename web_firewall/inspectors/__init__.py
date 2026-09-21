"""WAF Request Inspectors Package."""
from web_firewall.inspectors.url_inspector import URLInspector, URLInspectionResult
from web_firewall.inspectors.body_inspector import BodyInspector, BodyInspectionResult

__all__ = [
    "URLInspector",
    "URLInspectionResult",
    "BodyInspector",
    "BodyInspectionResult",
]
