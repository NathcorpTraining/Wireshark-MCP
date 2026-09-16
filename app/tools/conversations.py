from app.utils.tshark import run_tshark
from app.utils.pagination import paginate_text, DEFAULT_MAX_CHARS
from app.config import settings


async def analyze_conversations(
    pcap_path: str,
    conversation_type: str = "ip",
    offset: int = 0,
    max_chars: int = DEFAULT_MAX_CHARS
):

    cmd = [
        settings.TSHARK_PATH,
        "-r",
        pcap_path,
        "-q",
        "-z",
        f"conv,{conversation_type}"
    ]

    output = await run_tshark(cmd)

    chunk, meta = paginate_text(output, offset, max_chars)

    return {
        "conversation_type": conversation_type,
        "data": chunk,
        **meta
    }