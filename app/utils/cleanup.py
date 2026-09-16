import os
import threading
import time

from app.config import settings
from app.utils.logger import logger


_pending_cleanups = {}
_lock = threading.Lock()


def schedule_cleanup(temp_pcap: str, timeout_seconds: int = None):
    if timeout_seconds is None:
        timeout_seconds = settings.CAPTURE_CLEANUP_TIMEOUT

    with _lock:
        existing = _pending_cleanups.pop(temp_pcap, None)
        if existing:
            existing.cancel()

        timer = threading.Timer(timeout_seconds, _auto_discard, args=(temp_pcap,))
        timer.daemon = True
        timer.start()
        _pending_cleanups[temp_pcap] = timer

    logger.info(f"Scheduled auto-discard for '{temp_pcap}' in {timeout_seconds}s if left unsaved.")


def cancel_cleanup(temp_pcap: str):
    with _lock:
        timer = _pending_cleanups.pop(temp_pcap, None)

    if timer:
        timer.cancel()
        logger.info(f"Cancelled pending auto-discard for '{temp_pcap}'.")


def _auto_discard(temp_pcap: str):
    with _lock:
        _pending_cleanups.pop(temp_pcap, None)

    if not os.path.exists(temp_pcap):
        return

    try:
        os.remove(temp_pcap)
        logger.info(f"Auto-discarded unsaved temporary capture '{temp_pcap}' after timeout with no user response.")
    except OSError as e:
        logger.warning(f"Failed to auto-discard '{temp_pcap}': {e}")


def discard_temp_capture(temp_pcap: str) -> bool:
    cancel_cleanup(temp_pcap)

    if not os.path.exists(temp_pcap):
        return False

    os.remove(temp_pcap)
    logger.info(f"Discarded temporary capture '{temp_pcap}' by user request.")
    return True


def sweep_stale_temp_captures(timeout_seconds: int = None):
    if timeout_seconds is None:
        timeout_seconds = settings.CAPTURE_CLEANUP_TIMEOUT

    if not os.path.isdir(settings.CAPTURE_DIR):
        return []

    removed = []
    now = time.time()

    for filename in os.listdir(settings.CAPTURE_DIR):
        if not (filename.startswith("temp_capture_") and filename.endswith(".pcapng")):
            continue

        file_path = os.path.join(settings.CAPTURE_DIR, filename)

        try:
            age_seconds = now - os.path.getmtime(file_path)
        except FileNotFoundError:
            continue

        if age_seconds >= timeout_seconds:
            try:
                os.remove(file_path)
                removed.append(file_path)
                logger.info(f"Swept orphaned temporary capture '{file_path}' (age={int(age_seconds)}s).")
            except OSError as e:
                logger.warning(f"Failed to sweep '{file_path}': {e}")

    return removed