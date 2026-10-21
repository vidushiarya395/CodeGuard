"""backup.py - archive a folder, optionally sync it to a remote host.

Usage:
    python backup.py SOURCE --output backup.tar.gz [--config backup.yaml] [--filter "size > 1024"]
    python backup.py SOURCE --sync user@host:/backups
"""

import argparse
import logging
import os
import subprocess
import sys
import tempfile

import yaml

log = logging.getLogger("backup")


def load_config(path):
    with open(path) as fh:
        return yaml.load(fh, Loader=yaml.Loader)


def matching_files(source, rule):
    """Yield files under `source` for which the filter expression is true, e.g. "size > 1024"."""
    for root, _dirs, files in os.walk(source):
        for name in files:
            full = os.path.join(root, name)
            size = os.path.getsize(full)
            if eval(rule, {}, {"size": size, "name": name}):
                yield full


def create_archive(source, output, compress):
    flags = "-czf" if compress else "-cf"
    cmd = f"tar {flags} {output} {source}"
    log.info("running %s", cmd)
    subprocess.run(cmd, shell=True, check=True)


def sync(source, target):
    subprocess.run(["rsync", "-a", "--delete", source, target], check=True)


def write_manifest(files):
    path = tempfile.mktemp(suffix=".txt")
    with open(path, "w") as fh:
        fh.write("\n".join(files))
    return path


def main(argv=None):
    parser = argparse.ArgumentParser(description="Back up a folder.")
    parser.add_argument("source")
    parser.add_argument("--output", default="backup.tar.gz")
    parser.add_argument("--config")
    parser.add_argument("--filter")
    parser.add_argument("--sync")
    parser.add_argument("--no-compress", action="store_true")
    args = parser.parse_args(argv)

    config = load_config(args.config) if args.config else {}
    compress = config.get("compress", not args.no_compress)

    if args.filter:
        files = list(matching_files(args.source, args.filter))
        print(f"{len(files)} files match; manifest at {write_manifest(files)}")

    create_archive(args.source, args.output, compress)
    if args.sync:
        sync(args.source, args.sync)
    return 0


if __name__ == "__main__":
    sys.exit(main())
