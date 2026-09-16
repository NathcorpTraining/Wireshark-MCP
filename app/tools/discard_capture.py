from app.utils.cleanup import discard_temp_capture


async def discard_capture(temporary_capture: str):

    if "temp_capture" not in temporary_capture:
        return {
            "status": "error",
            "message": "This does not look like a temporary capture file created by capture_live."
        }

    try:
        deleted = discard_temp_capture(temporary_capture)
    except OSError as e:
        return {
            "status": "error",
            "message": "Failed to delete temporary capture file.",
            "error": str(e)
        }

    if not deleted:
        return {
            "status": "not_found",
            "message": "Temporary capture file not found. It may already have been auto-discarded after the cleanup timeout."
        }

    return {
        "status": "success",
        "message": "Temporary capture file discarded.",
        "discarded_capture": temporary_capture
    }