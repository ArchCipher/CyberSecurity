import struct
from exceptions import ScorpionError


def parse_gif(data: bytes) -> None:
    """
    6-byte signature
    screen descriptor: 2-byte width, 2-byte height, 1-byte packed flags,
      1-byte Background color index, 1-byte Pixel aspect ratio
    optional global color table
    block | block | block | ... | trailer (0x3B)

    Typical blocks:
      Extension: 0x21
          Image descriptor: 0x2C (optional local color table, LZW code-size byte,
        and image-data sub-blocks)
          Trailer: 0x3B (end of file)

    Sub-blocks:
      1-byte size | data bytes | 1-byte size | data bytes | ... | 0
    """

    def need(pos: int, size: int) -> None:
        if pos + size > len(data):
            raise ScorpionError("truncated GIF")

    def read_subblocks(pos: int) -> tuple[list[bytes], int]:
        blocks = []
        while True:
            need(pos, 1)
            size = data[pos]
            pos += 1
            if size == 0:
                return blocks, pos
            need(pos, size)
            blocks.append(data[pos : pos + size])
            pos += size

    if len(data) < 13:
        raise ScorpionError("not a valid GIF header")

    version = data[:6].decode("ascii")
    width, height, packed, background_index, aspect_ratio = struct.unpack_from(
        "<HHBBB", data, 6
    )
    print(f"  GIF version: {version}")
    print(f"  canvas: {width} x {height}")
    print(f"  background color index: {background_index}")
    if aspect_ratio:
        print(f"  pixel aspect ratio byte: {aspect_ratio}")

    p = 13
    # Skip the optional global color table.
    if packed & 0x80:
        table_size = 3 * (2 ** ((packed & 0x07) + 1))
        need(p, table_size)
        p += table_size
    frames = 0

    while p < len(data):
        marker = data[p]
        p += 1

        if marker == 0x3B:  # GIF trailer
            print(f"  frames: {frames}")
            return
        if marker == 0x21:  # extension
            need(p, 1)
            label = data[p]
            p += 1
            blocks, p = read_subblocks(p)
            if label == 0xFE:  # Comment Extension
                comment = b"".join(blocks).decode("latin-1", errors="replace")
                print(f"  comment: {comment}")
            elif label == 0xF9 and blocks and len(blocks[0]) == 4:
                # Graphic Control Extension: delay is in hundredths of a second.
                delay = int.from_bytes(blocks[0][1:3], "little")
                print(f"  frame delay: {delay / 100:.2f} seconds")
            elif label == 0xFF and blocks:
                print(f"  application extension: {blocks[0]!r}")
        elif marker == 0x2C:  # Image Descriptor
            need(p, 9)
            left, top, frame_width, frame_height, image_packed = struct.unpack_from(
                "<HHHHB", data, p
            )
            p += 9
            frames += 1
            print(f"  frame {frames}: {frame_width} x {frame_height} at ({left}, {top})")
            # Skip optional local color table.
            if image_packed & 0x80:
                table_size = 3 * (2 ** ((image_packed & 0x07) + 1))
                need(p, table_size)
                p += table_size
            # Skip LZW minimum-code-size byte and image-data sub-blocks.
            need(p, 1)
            p += 1
            _, p = read_subblocks(p)

        else:
            raise ScorpionError(f"unexpected GIF block marker 0x{marker:02X}")

    raise ScorpionError("GIF is missing trailer")
