import os
import shutil

from app.utils.cleanup import cancel_cleanup

async def save_capture(
    temporary_capture: str
):

    if not os.path.exists(temporary_capture):

        return {

            "status": "error",

            "message": (
                "Temporary capture file not found."
            )
        }

    cancel_cleanup(temporary_capture)

    filename = os.path.basename(
        temporary_capture
    )

    final_name = filename.replace(
        "temp_capture",
        "saved_capture"
    )

    final_path = os.path.join(

        os.path.dirname(temporary_capture),

        final_name
    )

    shutil.move(
        temporary_capture,
        final_path
    )

    return {

        "status": "success",

        "saved_capture": final_path
    }