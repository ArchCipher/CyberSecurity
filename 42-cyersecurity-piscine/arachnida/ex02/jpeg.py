import struct
from exceptions import ScorpionError

MARKER_NAMES = {
    0xD8: "SOI",  # start of image
    0xD9: "EOI",  # end of image
    0xDA: "SOS",  # start of scan
    0xDB: "DQT",  # quantization tables
    0xC4: "DHT",  # Huffman tables
    0xDD: "DRI",
    0xFE: "COM",  # comments
    0xE0: "APP0",  # JFIF header
    0xE1: "APP1",  # EXIF
    0xE2: "APP2",  # ICC colour profile
    0xC8: "JPG",  # jpg extension marker
    0xCC: "DAC",
}


def marker_name(marker: int) -> str:
    if 0xE0 <= marker <= 0xEF:
        return f"APP{marker - 0xE0}"
    if 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
        # frame header
        return "SOF"
    return MARKER_NAMES.get(marker, f"0x{marker:02X}")


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
            # print(f"{start:#08x} SOS - image data follows, stopping") # debug
            return
        if marker == 0x01 or 0xD0 <= marker <= 0xD7:
            # TEM or RST0-RST7 (restart markers)
            print(f"{start:#08x} {marker_name(marker)} (no length)")
            continue

        if pos + 2 > len(data):
            raise ScorpionError("file ends before segment length")
        length = int.from_bytes(data[pos : pos + 2], "big")
        if length < 2 or pos + length > len(data):
            raise ScorpionError(f"bad segment length {length} at {start:#x}")
        # print(
        #     f"{start:#08x} {marker_name(marker):5} length={length:5} payload={length - 2:5}"
        # ) # debug

        if marker == 0xE1:
            payload = data[pos + 2 : pos + length]
            if payload[:6] == b"Exif\x00\x00":
                tiff = payload[6:]
                print(f"Exif found: TIFF block {len(tiff)} bytes")
                print(f"  first 8 bytes: {tiff[:8].hex(' ')}")
                return tiff
            print(f"APP1 is not Exif: {payload[:20]!r}")

        payload = data[pos + 2 : pos + length]

        # SOF (Start Of Frame markers), excluding DHT (C4), JPG (C8), and DAC (CC)
        if 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
            if len(payload) >= 6:
                precision, height, width, components = struct.unpack_from(
                    ">BHHB", payload, 0
                )
                print(
                    f"  image: {width} x {height}, "
                    f"{precision}-bit, {components} component(s)"
                )
        elif marker == 0xE0 and payload.startswith(b"JFIF\x00"):
            if len(payload) >= 12:
                units, x_density, y_density = struct.unpack_from(">BHH", payload, 7)
                unit_name = {0: "unitless", 1: "dpi", 2: "dpcm"}.get(units, "unknown")
                print(f"  JFIF density: {x_density} x {y_density} {unit_name}")
        elif marker == 0xFE:  # JPEG Comment
            print(f"  comment: {payload.decode('latin-1', errors='replace')}")

        pos += length

    raise ScorpionError("missing EOI marker")
