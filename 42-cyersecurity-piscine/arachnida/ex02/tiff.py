import struct
from exceptions import ScorpionError
from collections import deque
from tag_names import TAG_NAMES

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

# size per type
TYPE_SIZES = {
    1: 1,  # BYTE
    2: 1,  # ASCII
    3: 2,  # SHORT
    4: 4,  # LONG
    5: 8,  # RATIONAL (2 4-byte values: numerator / denominator)
    6: 1,  # SBYTE
    7: 1,  # UNDEFINED
    8: 2,  # SSHORT
    9: 4,  # SSLONG
    10: 8,  # SRATIONAL
    11: 4,  # FLOAT
    12: 8,  # DOUBLE
}


def format_value(value) -> str:
    if isinstance(value, bytes):
        return value.hex(" ") if value else "(empty)"
    if isinstance(value, list):
        return ", ".join(
            f"{v[0]}/{v[1]}"
            if isinstance(v, tuple)
            else f"{v:g}"
            if isinstance(v, float)
            else str(v)
            for v in value
        )
    return str(value)


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
        data = tiff[offset : offset + total]

    endian = "<" if order == "little" else ">"
    if typ == 2:
        # ASCII
        return data.split(b"\x00", 1)[0].decode("latin-1")
    if typ in (1, 6, 7):
        # BYTE, SBYTE, UNDEFINED
        return data
    if typ in (3, 4, 8, 9):
        # SHORT, LONG, SSHORT, SLONG
        signed = typ in (8, 9)
        return [
            int.from_bytes(data[i : i + size], order, signed=signed)
            for i in range(0, total, size)
        ]
    if typ in (5, 10):
        # RATIONAL, SRATIONAL (2 4-byte values per item)
        signed = typ == 10
        fmt = endian + ("ii" if signed else "II")
        return [struct.unpack_from(fmt, data, i) for i in range(0, total, size)]
    if typ in (11, 12):
        # FLOAT and DOUBLE
        fmt = "f" if typ == 11 else "d"
        return [
            struct.unpack_from(endian + fmt, data, i)[0] for i in range(0, total, size)
        ]

    # should not reach below
    raise ScorpionError(f"unsupported TIFF type {typ}")


def read_one_ifd(tiff: bytes, offset: int, order: str, names: dict):
    """
    IFD offset:
    2 bytes  entry count
    N x 12   entries: tag(2) type(2) count(4) value/offset(4)
    4 bytes  offset of next IFD (0 = last)
    """
    if offset + 2 > len(tiff):
        raise ScorpionError(f"IFD offset at {offset} outside block")
    count = int.from_bytes(tiff[offset : offset + 2], order)
    print(f"IFD at offset {offset}: {count} entries")

    sub_ifds = []
    p = offset + 2
    endian = "<" if order == "little" else ">"
    for _ in range(count):
        if p + 12 > len(tiff):
            raise ScorpionError(f"IFD entry at {p} outside block")
        tag, typ, cnt, raw = struct.unpack_from(endian + "HHI4s", tiff, p)
        value = decode_entry(tiff, typ, cnt, raw, order)
        # print(f"tag=0x{tag:04X} type={typ:2} count={cnt:6} {format_value(value)}") # DEBUG
        name = names.get(tag, f"0x{tag:04X}")
        # print IFD
        print(f" {name:<28} {format_value(value)}")
        if tag in (0x8769, 0x8825) and value:
            #  ExifOffset, GPSInfo
            sub_ifds.append((tag, value[0]))
        p += 12

    if p + 4 > len(tiff):
        raise ScorpionError("next IFD pointer missing")
    next_ifd = int.from_bytes(tiff[p : p + 4], order)
    if next_ifd != 0:
        print(f"next IFD: {next_ifd}")

    return sub_ifds, next_ifd


def read_ifd(tiff: bytes, offset: int, order: str, names: dict):
    pending = deque([(offset, names, "IFD0")])
    visited = set()

    while pending:
        current_offset, current_names, label = pending.popleft()
        if current_offset == 0 or current_offset in visited:
            continue
        visited.add(current_offset)
        print(f"{label}:")
        sub_ifds, next_ifd = read_one_ifd(tiff, current_offset, order, current_names)

        for tag, sub_offset in sub_ifds:
            if tag == 0x8769:
                pending.append((sub_offset, EXIF_TAG_NAMES, "Exif IFD"))
            elif tag == 0x8825:
                pending.append((sub_offset, GPS_TAG_NAMES, "GPS IFD"))

        # next IFD is another image directory, such as a thumbnail
        if next_ifd:
            pending.append((next_ifd, TAG_NAMES, "Next IFD"))


def parse_tiff_header(tiff) -> tuple[str, int]:
    """
    bytes 0-1   "II" or "MM"
    bytes 2-3   magic = 42
    bytes 4-7   IFD0 offset
    """
    if tiff[:2] == b"II":
        order = "little"  # little-endian (Intel)
    elif tiff[:2] == b"MM":
        order = "big"  # big-endian (Motorola)
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

    print(f"TIFF {order}-endian, IFD0 starts at byte {ifd0_offset}")
    return order, ifd0_offset
