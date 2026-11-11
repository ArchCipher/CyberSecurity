#!/usr/bin/env python3

"""
./scropion FILE1 [FILE2 ...]

Process image files to extract EXIF metadata

NOTE:
1.
  !r calls repr(value) -> shows b'...' with non-printable bytes escaped
  !s calls str(value)
  !a calls ascii(value)
2. Example `#08x`
  x - hex lowercase
  # - alternate form: prefix number with 0x
  0 - pad with zeroes
  8 - total 8 field width incling 0x
3. IFD is image file directory, an index of entries
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

MARKER_NAMES = {
    0xD8: "SOI", # start of image
    0xD9: "EOI", # end of image
    0xDA: "SOS", # start of scan
    0xDB: "DQT", # quantization tables
    0xC4: "DHT", # Huffman tables
    0xDD: "DRI",
    0xFE: "COM",
    0xE0: "APP0", # JFIF header
    0xE1: "APP1", # EXIF
    0xE2: "APP2", # ICC colour profile
    0xC8: "JPG", # jpg extension marker
    0xCC: "DAC",
}

# size per type
TYPE_SIZES = {
    1: 1, # BYTE
    2: 1, # ASCII
    3: 2, # SHORT
    4: 4, # LONG
    5: 8, # RATIONAL (2 4-byte values: numerator / denominator)
    6: 1, # SBYTE
    7: 1, # UNDEFINED
    8: 2, # SSHORT
    9: 4, # SSLONG
    10: 8, # SRATIONAL
    11: 4, # FLOAT
    12: 8, # DOUBLE
}

TAG_NAMES = {
    0x0100: "ImageWidth",
    0x0101: "ImageLength",
    0x010d: "DocumentName",
    0x010E: "ImageDescription",
    0x010F: "Make",
    0x0110: "Model",
    0x0112: "Orientation",
    0x011A: "XResolution",
    0x011B: "YResolution",
    0x0128: "ResolutionUnit",
    0x0131: "Software",
    0x0132: "ModifyDate",
    0x013B: "Artist",
    0x013c: "HostComputer",
    0x0211: "YCbCrCoefficients",
    0x0213: "YCbCrPositioning",
    0x8298: "Copyright",
    0x8649: "PhotoshopSettings",
    0x8769: "ExifOffset",
    0x8825: "GPSInfo",
}

EXIF_TAG_NAMES = {
    0x829A: "ExposureTime",
    0x829D: "FNumber",
    0x8822: "ExposureProgram",
    0x8824: "SpectralSensitivity",
    0x8827: "ISO",
    0x9000: "ExifVersion",
    0x9003: "DateTimeOriginal",
    0x9004: "CreateDate",
    0x9010: "OffsetTime",
    0x9101: "ComponentsConfiguration",
    0x9102: "CompressedBitsPerPixel",
    0x9201: "ShutterSpeedValue",
    0x9202: "ApertureValue",
    0x9203: "BrightnessValue",
    0x9204: "ExposureCompensation",
    0x9205: "MaxApertureValue",
    0x9206: "SubjectDistance",
    0x9207: "MeteringMode",
    0x9208: "LightSource",
    0x9209: "Flash",
    0x920A: "FocalLength",
    0x9211: "ImageNumber",
    0x9212: "SecurityClassification",
    0x9213: "ImageHistory",
    0x9214: "SubjectArea",
    0x927C: "MakerNote",
    0x9286: "UserComment",
    0x9290: "SubSecTime",
    0x9291: "SubSecTimeOriginal",
    0x9292: "SubSecTimeDigitized",
    0xA000: "FlashpixVersion",
    0xA001: "ColorSpace",
    0xA002: "ExifImageWidth",
    0xA003: "ExifImageHeight",
    0xA004: "RelatedSoundFile",
    0xA20E: "FocalPlaneXResolution",
    0xA20F: "FocalPlaneYResolution",
    0xA210: "FocalPlaneResolutionUnit",
    0xA214: "SubjectLocation",
    0xA217: "SensingMethod",
    0xA300: "FileSource",
    0xA301: "SceneType",
    0xA401: "CustomRendered",
    0xA402: "ExposureMode",
    0xA403: "WhiteBalance",
    0xA404: "DigitalZoomRatio",
    0xA405: "FocalLengthIn35mmFormat",
    0xA406: "SceneCaptureType",
    0xA407: "GainControl",
    0xA408: "Contrast",
    0xA409: "Saturation",
    0xA40A: "Sharpness",
    0xA40C: "SubjectDistanceRange",
    0xA420: "ImageUniqueID",
    0xA430: "OwnerName",
    0xA431: "SerialNumber",
    0xA432: "LensInfo",
    0xA433: "LensMake",
    0xA434: "LensModel",
    0xA435: "LensSerialNumber",
    0xA436: "ImageTitle",
    0xA438: "ImageEditor",
    0xA439: "CameraFirmware",
    0xA43B: "ImageEditingSoftware",
    0xA43C: "MetadataEditingSoftware",
}

GPS_TAG_NAMES = {
    0x0000: "GPSVersionID",
    0x0001: "GPSLatitudeRef",
    0x0002: "GPSLatitude",
    0x0003: "GPSLongitudeRef",
    0x0004: "GPSLongitude",
    0x0005: "GPSAltitudeRef",
    0x0006: "GPSAltitude",
    0x0007: "GPSTimeStamp",
    0x0008: "GPSSatellites",
    0x0009: "GPSStatus",
    0x000A: "GPSMeasureMode",
    0x000B: "GPSDOP",
    0x000C: "GPSSpeedRef",
    0x000D: "GPSSpeed",
    0x000E: "GPSTrackRef",
    0x000F: "GPSTrack",
    0x0010: "GPSImgDirectionRef",
    0x0011: "GPSImgDirection",
    0x0012: "GPSMapDatum",
    0x001D: "GPSDateStamp",
    0x001E: "GPSDifferential",
}

class ScorpionError(Exception):
    """Base class for all errors"""

def marker_name(marker: int) -> str:
    if 0xE0 <= marker <= 0xEF:
        return f"APP{marker - 0xE0}"
    if 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
        # frame header
        return "SOF"
    return MARKER_NAMES.get(marker, f"0x{marker:02X}")

def decode_entry(tiff: bytes, typ: int, cnt: int, raw: bytes, order: str):
    size = TYPE_SIZES.get(typ)
    if size is None:
        raise ScorpionError(f"unknown tiff type {typ}")
    total = size * cnt
    if total <= 4:
        data = raw[:total]
    else:
        offset = int.from_bytes(raw, order)
        if offset + total > len(tiff):
            raise ScorpionError(f"value at {offset} (+{total}) outside block")
        data = tiff[offset: offset + total]

    if typ == 2:
        # ASCII
        return data.split(b"\x00", 1)[0].decode("latin-1")
    if typ in (1, 6, 7):
        # BYTE, SBYTE, UNDEFINED
        return data
    if typ in (3, 4, 8, 9):
        # SHORT, LONG, SSHORT, SLONG
        signed = typ in (8, 9)
        return [int.from_bytes(data[i:i+size], order, signed=signed) for i in range(0, total, size)]
    if typ in (5, 10):
        # RATIONAL, SRATIONAL (2 4-byte values per item)
        signed = typ == 10
        return [(int.from_bytes(data[i:i+4], order, signed=signed),
                int.from_bytes(data[i+4:i+8], order, signed=signed))
                for i in range(0, total, size)]

    return data # FLOAT, DOUBLE not decoded yet

def format_value(value)-> str:
    if isinstance(value, bytes):
        return value.hex(" ") if value else "(empty)"
    if isinstance(value, list):
        parts = []
        for v in value:
            parts.append(f"{v[0]}/{v[1]}" if isinstance(v, tuple) else str(v))
        return ", ".join(parts)
    return str(value)

def read_ifd(tiff: bytes, offset: int, order: str, names: dict):
    """
    IFD offset:
    2 bytes  entry count
    N x 12   entries: tag(2) type(2) count(4) value/offset(4)
    4 bytes  offset of next IFD (0 = last)
    """
    if offset + 2 > len(tiff):
        raise ScorpionError(f"IFD offset at {offset} outside block")
    count = int.from_bytes(tiff[offset:offset + 2], order)
    print(f"IFD at offset {offset}: {count} entries")

    entries = []
    p = offset + 2
    for _ in range(count):
        if p + 12 > len(tiff):
            raise ScorpionError(f"IFD entry at {p} outside block")
        tag = int.from_bytes(tiff[p:p + 2], order)
        typ = int.from_bytes(tiff[p + 2:p + 4], order)
        cnt = int.from_bytes(tiff[p + 4:p + 8], order)
        raw = tiff[p + 8:p + 12]
        entries.append((tag, typ, cnt, raw))
        value = decode_entry(tiff, typ, cnt, raw, order)
        # print(f"tag=0x{tag:04X} type={typ:2} count={cnt:6} {format_value(value)}")
        name = names.get(tag, f"0x{tag:04X}")
        print(f"{name:<28} {format_value(value)}")
        p += 12

    if p + 4 > len(tiff):
        raise ScorpionError("next IFD pointer missing")
    next_ifd = int.from_bytes(tiff[p:p + 4], order)
    print(f"next IFD: {next_ifd}")

def parse_tiff_header(tiff) -> tuple[str, int]:
    """
    bytes 0-1   "II" or "MM"
    bytes 2-3   magic = 42
    bytes 4-7   IFD0 offset
    """
    if tiff[:2] == b"II":
        endian = "<"
        label = "little-endian (Intel)"
        order = "little"
    elif tiff[:2] == b"MM":
        endian = ">"
        label = "big-endian (Motorola)"
        order = "big"
    else:
        raise ScorpionError(f"not a tiff block: {tiff[:2]!r}")

    if len(tiff) < 8:
        raise ScorpionError("tiff header truncated")
    magic = int.from_bytes(tiff[2:4], order)
    ifd0_offset = int.from_bytes(tiff[4:8], order)
    if magic != 42:
        raise ScorpionError(f"bad tiff magic block {magic} (expected 42)")
    if ifd0_offset >= len(tiff):
        raise ScorpionError(f"ifd0 offset {ifd0_offset} outside block")

    print(f"TIFF {label}, IFD0 starts at byte {ifd0_offset}")
    return order, ifd0_offset

def parse_jpeg(data: bytes) -> bytes | None:
    """
    parse jpg file and print markers
    """
    pos = 2
    while pos < len(data):
        start = pos
        if data[pos] != 0xFF:
            raise ScorpionError(f"expected a marker at offset {pos:#x}")
        while pos < len(data) and data[pos] == 0xFF:
            pos += 1
        if pos >= len(data):
            raise ScorpionError("file ends in middle of a marker")
        marker = data[pos]
        pos += 1

        if marker == 0xD9:
            print(f"{start:#08x} EOI")
            return
        if marker == 0xDA:
            print(f"{start:#08x} SOS - image data follows, stopping")
            return
        if marker == 0x01 or 0xD0 <= marker <= 0xD7:
            # TEM or RST0-RST7 (restart markers)
            print(f"{start:#08x} {marker_name(marker)} (no length)")
            continue

        if pos + 2 > len(data):
            raise ScorpionError("file ends before segment length")
        length = int.from_bytes(data[pos:pos + 2], "big")
        if length < 2 or pos + length > len(data):
            raise ScorpionError(f"bad segment length {length} at {start:#x}")
        print(f"{start:#08x} {marker_name(marker):5} length={length:5} payload={length - 2:5}")

        if marker == 0xE1:
            payload = data[pos + 2:pos + length]
            if payload[:6] == b"Exif\x00\x00":
                tiff = payload[6:]
                print(f"Exif found: TIFF block {len(tiff)} bytes")
                print(f"first 8 bytes: {tiff[:8].hex(' ')}")
                return tiff
            print(f"APP1 is not Exif: {payload[:20]!r}")

        pos += length

    raise ScorpionError("missing EOI marker")


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
