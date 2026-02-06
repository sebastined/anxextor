#!/usr/bin/env python3
import argparse
import subprocess
import sys


def run(cmd, capture_output=False):
    if capture_output:
        result = subprocess.run(cmd, check=True, text=True, stdout=subprocess.PIPE)
        return result.stdout.strip()
    subprocess.run(cmd, check=True)
    return ""


def ensure_git():
    try:
        run(["git", "--version"])
    except Exception:
        print("git is not available in PATH.", file=sys.stderr)
        sys.exit(1)

    try:
        run(["git", "rev-parse", "--git-dir"], capture_output=True)
    except Exception:
        print("Current directory is not a git repository.", file=sys.stderr)
        sys.exit(1)


def promote_house(args):
    run(["git", "fetch", args.remote, args.slave_branch, args.house_branch])
    ahead = run(
        [
            "git",
            "rev-list",
            "--count",
            f"{args.remote}/{args.house_branch}..{args.remote}/{args.slave_branch}",
        ],
        capture_output=True,
    )
    try:
        ahead_count = int(ahead)
    except ValueError:
        print("Could not parse ahead count.", file=sys.stderr)
        sys.exit(1)

    print(f"Slave is ahead of house by {ahead_count} commits.")
    if ahead_count < args.threshold:
        print("Threshold not met. No promotion.")
        return

    run(["git", "checkout", args.house_branch])
    run(["git", "pull", args.remote, args.house_branch])
    run(
        [
            "git",
            "merge",
            "--no-ff",
            f"{args.remote}/{args.slave_branch}",
            "-m",
            f"Promote {args.slave_branch} -> {args.house_branch}",
        ]
    )

    if args.push:
        run(["git", "push", args.remote, args.house_branch])
        print(f"Promotion pushed to {args.remote}/{args.house_branch}.")
    else:
        print("Promotion completed locally. Use --push to push to remote.")


def promote_master(args):
    run(["git", "fetch", args.remote, args.house_branch, args.master_branch])
    run(["git", "checkout", args.master_branch])
    run(["git", "pull", args.remote, args.master_branch])
    run(
        [
            "git",
            "merge",
            "--no-ff",
            f"{args.remote}/{args.house_branch}",
            "-m",
            f"Promote {args.house_branch} -> {args.master_branch}",
        ]
    )

    if args.push:
        run(["git", "push", args.remote, args.master_branch])
        print(f"Promotion pushed to {args.remote}/{args.master_branch}.")
    else:
        print("Promotion completed locally. Use --push to push to remote.")


def build_parser():
    parser = argparse.ArgumentParser(
        description="Branch promotion helpers for anxextor.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    house = subparsers.add_parser("house", help="Promote slave -> house")
    house.add_argument("--remote", default="origin", help="Git remote name")
    house.add_argument("--slave-branch", default="slave", help="Slave branch")
    house.add_argument("--house-branch", default="house", help="House branch")
    house.add_argument("--threshold", type=int, default=3, help="Commit threshold")
    house.add_argument("--push", action="store_true", help="Push after merge")
    house.add_argument("--simulate", action="store_true", help="No git commands")
    house.set_defaults(handler=promote_house)

    master = subparsers.add_parser("master", help="Promote house -> master")
    master.add_argument("--remote", default="origin", help="Git remote name")
    master.add_argument("--house-branch", default="house", help="House branch")
    master.add_argument("--master-branch", default="master", help="Master branch")
    master.add_argument("--push", action="store_true", help="Push after merge")
    master.add_argument("--simulate", action="store_true", help="No git commands")
    master.set_defaults(handler=promote_master)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.simulate:
        print("Simulation only. No git commands executed.")
        return

    ensure_git()
    args.handler(args)


if __name__ == "__main__":
    main()
