from app.utils.tshark import run_tshark
from app.utils.pagination import paginate_text
from app.config import settings

# Stay well under the MCP platform's 1MB response cap. JSON-encoding
# can expand raw text (escaped newlines/quotes/control chars), so we
# leave generous headroom rather than chunking close to the limit.
MAX_CHUNK_CHARS = 300_000


async def inspect_stream(
    pcap_path: str,
    stream_type: str,
    stream_id: int,
    offset: int = 0,
    max_chars: int = MAX_CHUNK_CHARS
):

    cmd = [
        settings.TSHARK_PATH,
        "-r",
        pcap_path,
        "-q",
        "-z",
        f"follow,{stream_type},ascii,{stream_id}"
    ]

    output = await run_tshark(cmd)

    chunk, meta = paginate_text(output, offset, max_chars)

    return {
        "stream_data": chunk,
        **meta
    }