#!/usr/bin/env python3
"""Launch the APT-Hunter web dashboard for a generated report.

Usage:
    python3 run_webapp.py <path-to-Report.xlsx | output-directory> [--host HOST] [--port PORT]
"""
import argparse
import glob
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from webapp.server import create_app  # noqa: E402


def resolve_report_path(path):
    if os.path.isdir(path):
        candidates = sorted(glob.glob(os.path.join(path, "*_Report.xlsx")))
        if not candidates:
            raise SystemExit(f"No *_Report.xlsx file found in directory: {path}")
        return candidates[0]
    return path


def main():
    parser = argparse.ArgumentParser(description="APT-Hunter web dashboard")
    parser.add_argument(
        "report",
        help="Path to an APT-Hunter *_Report.xlsx file, or the output directory containing one",
    )
    parser.add_argument("--host", default="0.0.0.0", help="Interface to bind to (default 0.0.0.0)")
    parser.add_argument("--port", type=int, default=5000, help="Port to listen on (default 5000)")
    parser.add_argument(
        "--rebuild", action="store_true",
        help="Force rebuilding the cache database from the xlsx file even if it looks up to date",
    )
    parser.add_argument("--debug", action="store_true", help="Run Flask in debug/reload mode")
    args = parser.parse_args()

    report_path = resolve_report_path(args.report)
    if not os.path.isfile(report_path):
        raise SystemExit(f"Report file not found: {report_path}")

    print(f"Loading report: {report_path}")
    app = create_app(report_path, force_rebuild=args.rebuild)
    print(f"APT-Hunter dashboard ready -> http://{args.host}:{args.port}/")
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)


if __name__ == "__main__":
    main()
