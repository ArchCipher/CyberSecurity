from exceptions import ScorpionError
from tiff import parse_tiff_header, read_ifd
from tag_names import TAG_NAMES
import struct
import zlib


def split_nul(data: bytes, start: int) -> tuple[bytes, int]:
    """Return bytes before the next NUL and the position after it."""
    end = data.find(b"\0", start)
    if end < 0:
        raise ScorpionError("malformed PNG text chunk: missing NUL separator")
    return data[start:end], end + 1


def inflate_text(data: bytes, limit: int = 1_000_000) -> bytes:
    """Decompress text with a maximum output size."""
    dec = zlib.decompressobj()
    text = dec.decompress(data, limit + 1)
    if len(text) > limit or dec.unconsumed_tail:
        raise ScorpionError("PNG text exceeds decompression limit")
    text += dec.flush()
    if len(text) > limit:
        raise ScorpionError("PNG text exceeds decompression limit")
    return text


def parse_png_text(typ: bytes, chunk_data: bytes) -> dict:
    """
    tEXt (Latin-1):
      variable-length keyword, NUL separator, text
    zTXt (deflate-compressed):
      variable-length keyword, NUL separator, one-byte method, compressed text
    iTXt (UTF-8, optionally compressed):
      variable-length keyword, NUL separator, two one-byte fields, variable-length language tag, NUL separator,
      variable-length translated keyword, NUL separator, text
    """

    keyword, pos = split_nul(chunk_data, 0)
    if not 1 <= len(keyword) <= 79:
        raise ScorpionError("invalid PNG text keyword")

    if typ == b"tEXt":
        raw_text = chunk_data[pos:]
        return {
            "keyword": keyword.decode("latin-1"),
            "text": raw_text.decode("latin-1"),
        }
    if typ == b"zTXt":
        if pos >= len(chunk_data):
            raise ScorpionError("truncated zTXt chunk")
        method = chunk_data[pos]
        if method != 0:
            raise ScorpionError(f"unsupported zTXt compression method: {method}")
        raw_text = inflate_text(chunk_data[pos + 1 :])
        return {
            "keyword": keyword.decode("latin-1"),
            "text": raw_text.decode("latin-1"),
        }
    if typ == b"iTXt":
        if pos + 2 > len(chunk_data):
            raise ScorpionError("truncated iTXt chunk")
        compression_flag = chunk_data[pos]
        compression_method = chunk_data[pos + 1]
        pos += 2
        language, pos = split_nul(chunk_data, pos)
        translated_keyword, pos = split_nul(chunk_data, pos)
        raw_text = chunk_data[pos:]
        if compression_flag not in (0, 1):
            raise ScorpionError("invalid iTXt compression flag")
        if compression_method != 0:
            raise ScorpionError(
                f"unsupported iTXt compression method: {compression_method}"
            )
        if compression_flag == 1:
            raw_text = inflate_text(raw_text)
        try:
            return {
                "keyword": keyword.decode("latin-1"),
                "language": language.decode("ascii"),
                "translated_keyword": translated_keyword.decode("utf-8"),
                "text": raw_text.decode("utf-8"),
            }
        except UnicodeDecodeError as exc:
            raise ScorpionError("invalid encoding in iTXt chunk") from exc

    raise ScorpionError(f"not a PNG text chunk: {typ!r}")


def parse_png(data: bytes) -> None:
    """
    8-byte PNG signature | IHDR chunk | IDAT and other metadata chunks | IEND chunk

    Each chunk:
    4-byte data length | 4-byte chunk type | N-byte chunk data | 4-byte CRC

    IHDR has 13 data bytes
    """
    if len(data) < 33:
        raise ScorpionError("truncated PNG info header")
    p = 8
    ihdr_length = int.from_bytes(data[p : p + 4], "big")
    if ihdr_length != 13 or data[p + 4 : p + 8] != b"IHDR":
        raise ScorpionError("PNG does not start with a valid IHDR chunk")
    width, height, bit_depth, color_type, compression, filter_method, interlace = (
        struct.unpack_from(">IIBBBBB", data, p + 8)
    )
    print(
        f"  image: {width} x {height}, color type: {color_type}, bit depth: {bit_depth}"
    )
    print(
        f"  compression: {compression}, filter method: {filter_method}, interlace method: {interlace}"
    )
    p += 12 + ihdr_length
    while p + 12 <= len(data):
        length = int.from_bytes(data[p : p + 4], "big")
        typ = data[p + 4 : p + 8]
        chunk_end = p + 12 + length
        if chunk_end > len(data):
            raise ScorpionError("truncated PNG chunk")
        if typ == b"IEND":
            break

        if typ in (b"tEXt", b"zTXt", b"iTXt", b"eXIf"):
            print(f"  type: {typ.decode('ascii', errors='replace')} length: {length}")
        chunk_data = data[p + 8 : p + 8 + length]
        if typ in (b"tEXt", b"zTXt", b"iTXt"):
            info = parse_png_text(typ, chunk_data)
            print(f"    {info['keyword']}: {info['text']}")
        elif typ == b"eXIf":
            order, ifd0_offset = parse_tiff_header(chunk_data)
            read_ifd(chunk_data, ifd0_offset, order, TAG_NAMES)
        p = chunk_end
