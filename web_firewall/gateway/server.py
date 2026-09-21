"""Server Entry Point for Running the WAF Gateway with Uvicorn and Auto-Reload Debugger."""
import os
import sys
from pathlib import Path
import uvicorn
from web_firewall.config.settings import get_settings


def main():
    """Run the WAF ASGI server with Auto-Reload Debugger."""
    # Ensure project root is in sys.path
    project_root = Path(__file__).resolve().parent.parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    settings = get_settings()
    waf_dir = str(Path(__file__).resolve().parent.parent)
    reload_enabled = os.getenv("WAF_RELOAD", str(settings.RELOAD)).lower() in ("true", "1", "yes")

    print(f"[*] Starting Layer-7 WAF Gateway with Auto-Reload Debugger on http://{settings.HOST}:{settings.PORT} (reload={reload_enabled})...")
    uvicorn.run(
        "web_firewall.gateway.proxy:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=reload_enabled,
        reload_dirs=[waf_dir] if reload_enabled else None,
        access_log=False,  # WAF produces its own structured security audit logs
        log_level=settings.LOG_LEVEL.lower(),
    )


if __name__ == "__main__":
    main()
