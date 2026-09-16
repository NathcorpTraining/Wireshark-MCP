DEFAULT_MAX_CHARS = 200_000


def paginate_text(text: str, offset: int = 0, max_chars: int = DEFAULT_MAX_CHARS):
    """
    Slice `text` into a bounded chunk starting at `offset`.

    Returns (chunk, meta) where `meta` is a dict of pagination fields
    the caller should merge into its own response alongside the chunk
    under whatever key name makes sense for that tool.
    """

    total_length = len(text)

    chunk = text[offset:offset + max_chars]

    next_offset = offset + len(chunk)

    truncated = next_offset < total_length

    meta = {

        "offset": offset,

        "returned_length": len(chunk),

        "total_length": total_length,

        "truncated": truncated,

        "next_offset": next_offset if truncated else None,

        "message": (
            f"Returned characters {offset}-{next_offset} of "
            f"{total_length}. Call this tool again with "
            f"offset={next_offset} to get the next chunk."
            if truncated else
            "Full result returned."
        )
    }

    return chunk, meta