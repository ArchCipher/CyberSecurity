#!/usr/bin/env python3

"""
./scropion FILE1 [FILE2 ...]

Process image files to extract EXIF metadata
"""

import argparse
import sys
from pathlib import Path

MAGIC = {
    b"\xff\xd8": "JPEG",
    b"\x89PNG\r\n\x1a\n": "PNG",
    b"GIF87a": "GIF",
    b"GIF89a": "GIF",
    b"BM": "BMP"
}

class ScorpionError(Exception):
    """Base class for all errors"""

def detect_format(data: bytes) -> str:
    for magic, name in MAGIC.items():
        if data.startswith(magic):
            return name
    raise ScorpionError("unrecognised file format")

def process_file(path: Path) -> None:
    """Process an image file to extract EXIF metadata."""
    data = path.read_bytes()
    print(f"== {path} ({len(data)} bytes) ==")
    print(f"format: {detect_format(data)}")

def parse_args(argv=None) -> argparse.Namespace:
    """
    ./scropion FILE1 [FILE2 ...]
    """
    parser = argparse.ArgumentParser(prog="scorpion", description="Extract EXIF information from digital image files.")
    parser.add_argument("files", metavar="FILE", nargs="+", help="files to process")
    args = parser.parse_args(argv)
    return args

def main(argv=None) -> None:
    args = parse_args(argv)
    for name in args.files:
        try:
            process_file(Path(name))
        except (OSError, ScorpionError) as e:
            print(f"{name}: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()
