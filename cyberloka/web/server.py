"""`cyberloka-web` CLI to launch the dashboard."""
from __future__ import annotations

import argparse
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cyberloka-web",
        description="Jalankan Cyberloka dashboard (FastAPI + Uvicorn).",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--reload", action="store_true")
    args = parser.parse_args(argv)

    try:
        import uvicorn
    except ImportError:
        print(
            "uvicorn / fastapi belum terpasang. Jalankan:\n"
            "  pip install 'cyberloka[web]'\n"
            "atau:\n"
            "  pip install fastapi 'uvicorn[standard]'",
            file=sys.stderr,
        )
        return 1

    uvicorn.run(
        "cyberloka.web.app:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info",
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
