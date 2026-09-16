import logging
import os

from app.config import settings


os.makedirs(settings.LOG_DIR, exist_ok=True)

logger = logging.getLogger("wireshark_mcp")
logger.setLevel(settings.LOG_LEVEL)

if not logger.handlers:

    formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s"
    )

    file_handler = logging.FileHandler(
        os.path.join(settings.LOG_DIR, "wireshark_mcp.log")
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)