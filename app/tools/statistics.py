from app.utils.tshark import run_tshark
from app.utils.pagination import paginate_text, DEFAULT_MAX_CHARS
from app.config import settings


async def protocol_statistics(
    pcap_path: str,
    offset: int = 0,
    max_chars: int = DEFAULT_MAX_CHARS
):

    cmd = [
        settings.TSHARK_PATH,
        "-r",
        pcap_path,
        "-q",
        "-z",
        "io,stat,1"
    ]

    output = await run_tshark(cmd)

    chunk, meta = paginate_text(output, offset, max_chars)

    return {
        "statistics": chunk,
        **meta
    }