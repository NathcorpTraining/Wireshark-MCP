import asyncio
import subprocess
import sys

from app.config import settings


def _kill_process_tree(pid: int):
    """
    Kill a process AND all its children.

    This matters specifically for tshark on Windows: tshark.exe does
    not capture packets itself, it spawns dumpcap.exe as a child
    process to do the actual capture. subprocess.run(timeout=...)
    only terminates the immediate child (tshark.exe) on timeout - it
    does NOT touch dumpcap.exe, which is left running as an orphan
    and keeps the output .pcapng file open/locked. That lock is why
    the scheduled cleanup later fails to delete the temp file
    (PermissionError / WinError 32: file in use), leaving an
    orphaned temp capture on disk indefinitely.

    Killing the whole process tree ensures dumpcap.exe (or any
    other child) is also terminated, releasing the file handle, so
    the subsequent cleanup delete actually succeeds.
    """

    if sys.platform == "win32":

        # /T = kill the whole process tree, /F = force
        subprocess.run(
            ["taskkill", "/PID", str(pid), "/T", "/F"],
            capture_output=True
        )

    else:

        import os
        import signal

        try:

            # Requires the child to have been started in its own
            # process group (see start_new_session=True below).
            os.killpg(os.getpgid(pid), signal.SIGKILL)

        except ProcessLookupError:

            pass


def _run_subprocess(cmd: list, timeout: int):
    """
    Blocking subprocess call - always invoked via asyncio.to_thread
    from run_tshark() below, never directly from async code, so a
    long-running capture doesn't freeze the event loop.
    """

    popen_kwargs = {}

    if sys.platform != "win32":

        # Puts the child in its own process group so we can kill
        # the whole tree (tshark + any children) with os.killpg on
        # timeout, mirroring the taskkill /T behavior on Windows.
        popen_kwargs["start_new_session"] = True

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        **popen_kwargs
    )

    try:

        stdout, stderr = process.communicate(timeout=timeout)

    except subprocess.TimeoutExpired as e:

        # Kill the FULL process tree (not just `process`) so any
        # child (e.g. dumpcap.exe) releases its lock on the output
        # file before we raise - otherwise the temp pcap can't be
        # deleted later even though cleanup is correctly scheduled.
        _kill_process_tree(process.pid)

        # Drain pipes now that the tree is dead, so the process
        # doesn't linger as a zombie.
        try:
            process.communicate(timeout=5)
        except Exception:
            pass

        raise RuntimeError(
            f"tshark did not finish within {timeout}s: {' '.join(cmd)}"
        ) from e

    if process.returncode != 0:
        raise RuntimeError(stderr)

    return stdout


async def run_tshark(cmd: list, timeout: int = None):

    if timeout is None:
        timeout = settings.MAX_TIMEOUT

    # Offload the blocking subprocess call to a worker thread so the
    # event loop stays free to handle MCP protocol traffic while
    # tshark is running - critical for long captures (multiple
    # minutes).
    return await asyncio.to_thread(_run_subprocess, cmd, timeout)