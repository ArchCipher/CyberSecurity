#!/usr/bin/env python3

"""
./scropion FILE1 [FILE2 ...]

Process image files to extract EXIF metadata

NOTE:
1. IFD is image file directory, an index of entries
2. struct format codes (with < or >):
  <  little-endian
  >  big-endian
  B  unsigned 1-byte integer
  H  unsigned 2-byte integer
  h  signed 2-byte integer
  I  unsigned 4-byte integer
  i  signed 4-byte integer
  4s four raw bytes
3.
  !r calls repr(value) -> shows b'...' with non-printable bytes escaped
  !s calls str(value)
  !a calls ascii(value)
4. Example `#08x`
  x - hex lowercase
  # - alternate form: prefix number with 0x
  0 - pad with zeroes
  8 - total 8 field width incling 0x

"""

from exceptions import ScorpionError
from jpeg import parse_jpeg
from png import parse_png
from gif import parse_gif
from bmp import parse_bmp
from tiff import parse_tiff_header, read_ifd
from tag_names import TAG_NAMES
import argparse
import sys
from pathlib import Path

MAGIC = {
    b"\xff\xd8": "JPEG",
    b"\x89PNG\r\n\x1a\n": "PNG",
    b"GIF87a": "GIF",
    b"GIF89a": "GIF",
    b"BM": "BMP",
}


def detect_format(data: bytes) -> str:
    for magic, name in MAGIC.items():
        if data.startswith(magic):
            return name
    raise ScorpionError("unrecognised file format")


def process_file(path: Path) -> None:
    """Process an image file to extract EXIF metadata."""
    data = path.read_bytes()
    print(f"== {path} ({len(data)} bytes) ==")
    fmt = detect_format(data)
    print(f"format: {fmt}")
    if fmt == "JPEG":
        tiff = parse_jpeg(data)
        if tiff is None:
            print("No exif block found")
        else:
            order, ifd0_offset = parse_tiff_header(tiff)
            read_ifd(tiff, ifd0_offset, order, TAG_NAMES)
    elif fmt == "BMP":
        parse_bmp(data)
    elif fmt == "PNG":
        parse_png(data)
    elif fmt == "GIF":
        parse_gif(data)


def parse_args(argv=None) -> argparse.Namespace:
    """
    ./scropion FILE1 [FILE2 ...]
    """
    parser = argparse.ArgumentParser(
        prog="scorpion",
        description="Extract EXIF information from digital image files.",
    )
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
