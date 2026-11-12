import struct
from exceptions import ScorpionError


def parse_bmp(data: bytes) -> None:
    """
    BITMAPFILEHEADER  14 bytes
    DIB header        12 / 40 / 108 / 124
    """
    if len(data) < 26:
        raise ScorpionError("truncated BMP info header")

    dib_size = int.from_bytes(data[14:18], "little")
    if len(data) < 14 + dib_size:
        raise ScorpionError("truncated BMP info header")
    fields_offset = 14 + 4  # BITMAPFILEHEADER + DIB size indicator

    if dib_size == 12:  # BITMAPCOREHEADER
        width, height, plane, bits_per_pixel = struct.unpack_from(
            "<HHHH", data, fields_offset
        )
        # plane (2 bytes) indicates number of color planes (must be 1)
        print(f"image: {width} x {height}, {bits_per_pixel} bits per pixel")
        return
    # 40 BITMAPINFOHEADER, 108 BITMAPV4HEADER, 124 BITMAPV5HEADER
    if dib_size >= 40:
        width, height, plane, bits_per_pixel, compression, image_size, x_ppm, y_ppm = (
            struct.unpack_from("<iiHHIIii", data, fields_offset)
        )
        print(f"image: {width} x {abs(height)}, {bits_per_pixel} bits per pixel")
        print(f"compression: {compression}")
        print(f"image size: {image_size}")
        print(f"resolution: {x_ppm} x {y_ppm} pixels per meter")
        return

    raise ScorpionError(f"unsupported BMP DIB header size {dib_size}")
