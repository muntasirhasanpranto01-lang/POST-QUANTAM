from __future__ import annotations

import argparse
import uvicorn


def main() -> None:
    parser = argparse.ArgumentParser(prog="pqctool")
    sub = parser.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve", help="Run the API")
    serve.add_argument("--host", default="0.0.0.0")
    serve.add_argument("--port", default=8000, type=int)
    serve.add_argument("--workers", default=1, type=int)
    serve.add_argument("--reload", action="store_true")
    args = parser.parse_args()
    if args.command == "serve":
        uvicorn.run("pq_backend.main:app", host=args.host, port=args.port, workers=args.workers, reload=args.reload)


if __name__ == "__main__":
    main()
