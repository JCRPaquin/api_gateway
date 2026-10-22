"""Issue an operator-managed bearer through the gateway's policy service."""

import argparse
import json
import os
import sys
from pathlib import Path

PROJECT_HOME = str(Path(__file__).resolve().parent.parent)
if PROJECT_HOME not in sys.path:
    sys.path.append(PROJECT_HOME)

from apigateway.app import create_app


def _route_capacities(value):
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError) as error:
        raise argparse.ArgumentTypeError("route capacities must be JSON") from error
    if not isinstance(parsed, dict):
        raise argparse.ArgumentTypeError("route capacities must be a JSON object")
    return parsed


def add_arguments(parser):
    parser.add_argument(
        "--user-email",
        required=True,
        help="Existing active credential owner's exact email address",
    )
    parser.add_argument("--name", required=True, help="OAuth client display name")
    parser.add_argument("--scopes", nargs="+", help="Requested scopes")
    parser.add_argument(
        "--expires-in",
        type=int,
        help="Relative lifetime in seconds (maximum 30 days)",
    )
    parser.add_argument("--ratelimit", type=float, default=1.0)
    parser.add_argument(
        "--route-capacities",
        type=_route_capacities,
        help="JSON object keyed by exact registered Flask endpoint",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="'-' for stdout or a new mode-0600 file receiving only the raw token",
    )


def get_token(app=None, argv=None):
    """Return one newly issued raw token to an explicit in-process caller."""
    parser = argparse.ArgumentParser()
    add_arguments(parser)
    args = parser.parse_args(argv)
    app = app or create_app()
    with app.app_context():
        issued = app.auth_service.issue_credential(
            args.user_email,
            purpose="operator",
            scopes=args.scopes,
            expires_in=args.expires_in,
            client_name=args.name,
            ratelimit_multiplier=args.ratelimit,
            individual_ratelimit_multipliers=args.route_capacities,
        )
        return issued.access_token


def main(argv=None):
    parser = argparse.ArgumentParser()
    add_arguments(parser)
    args = parser.parse_args(argv)
    output_fd = None
    output_path = None
    if args.output != "-":
        output_path = os.path.abspath(args.output)
        output_fd = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.fchmod(output_fd, 0o600)
    try:
        token = get_token(
            argv=[
                "--user-email",
                args.user_email,
                "--name",
                args.name,
                *(["--scopes", *args.scopes] if args.scopes else []),
                *(
                    ["--expires-in", str(args.expires_in)]
                    if args.expires_in is not None
                    else []
                ),
                "--ratelimit",
                str(args.ratelimit),
                *(
                    ["--route-capacities", json.dumps(args.route_capacities)]
                    if args.route_capacities is not None
                    else []
                ),
                "--output",
                args.output,
            ]
        )
        if output_fd is None:
            sys.stdout.write(token + "\n")
        else:
            os.write(output_fd, (token + "\n").encode("ascii"))
    except Exception:
        if output_fd is not None:
            os.close(output_fd)
            output_fd = None
            os.unlink(output_path)
        raise
    finally:
        if output_fd is not None:
            os.close(output_fd)


if __name__ == "__main__":
    main()