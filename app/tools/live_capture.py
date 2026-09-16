import asyncio
import json
import os
import re
from datetime import datetime

from app.utils.tshark import run_tshark
from app.utils.cleanup import schedule_cleanup, cancel_cleanup
from app.utils.capture_jobs import create_job, update_job, get_job
from app.config import settings


# =====================================================
# PUBLIC ENTRY POINT #1: start_live_capture
#
# This is the MCP tool the client should call to KICK OFF a
# capture. It does the fast synchronous prep work (list/validate
# interfaces) and then hands the actual capture+analysis off to a
# background asyncio task via asyncio.create_task(). It returns
# almost immediately with a job_id - it does NOT wait for the
# capture to finish. This is what avoids hitting the MCP client's
# own tool-call timeout (~4 min observed), regardless of how long
# `duration` is.
# =====================================================

async def start_live_capture(
    interface: str = None,
    duration: int = 10,
    capture_filter: str = None,
    save_capture: bool = False
):

    # ---------------------------------------------------
    # Get Available Interfaces
    # ---------------------------------------------------

    list_cmd = [
        settings.TSHARK_PATH,
        "-D"
    ]

    interface_output = await run_tshark(list_cmd)

    available_interfaces = []

    for line in interface_output.splitlines():

        line = line.strip()

        if line:

            available_interfaces.append(line)

    # ---------------------------------------------------
    # Ask User to Select Interface
    # ---------------------------------------------------

    if not interface:

        return {

            "status": "user_input_required",

            "message": (
                "Multiple interfaces are available. "
                "Select one for live capture."
            ),

            "available_interfaces": available_interfaces
        }

    # ---------------------------------------------------
    # Validate Interface (index/description match only,
    # never a raw-line substring match - see earlier fix)
    # ---------------------------------------------------

    exact_match = None
    partial_match = None

    for item in available_interfaces:

        idx_part, _, rest = item.partition(".")
        idx_part = idx_part.strip()

        desc_match = re.search(r'\(([^)]*)\)\s*$', rest)
        description = (
            desc_match.group(1).strip()
            if desc_match
            else rest.strip()
        )

        if interface == idx_part:

            exact_match = item
            break

        if interface.lower() == description.lower():

            exact_match = item
            break

        if (
            partial_match is None
            and interface.lower() in description.lower()
        ):

            partial_match = item

    matched_interface = exact_match or partial_match

    if not matched_interface:

        return {

            "status": "invalid_interface",

            "message": "Invalid interface selected.",

            "available_interfaces": available_interfaces
        }

    interface_id = matched_interface.split(".", 1)[0].strip()

    # ---------------------------------------------------
    # Create Job + Launch Background Task
    #
    # asyncio.create_task() schedules the coroutine to run on the
    # event loop WITHOUT blocking here. We return the job_id to
    # the caller right away. The actual capture happens in
    # _run_capture_job below, completely decoupled from this
    # request/response cycle.
    # ---------------------------------------------------

    job_id = create_job()

    update_job(
        job_id,
        status="capturing",
        progress={
            "elapsed_seconds": 0,
            "total_seconds": duration
        }
    )

    asyncio.create_task(
        _run_capture_job(
            job_id=job_id,
            matched_interface=matched_interface,
            interface_id=interface_id,
            duration=duration,
            capture_filter=capture_filter,
            save_capture=save_capture
        )
    )

    return {

        "status": "capture_started",

        "job_id": job_id,

        "interface": matched_interface,

        "duration": duration,

        "message": (
            f"Capture started in the background on "
            f"'{matched_interface}' for {duration} seconds. "
            "Poll get_capture_status with this job_id to check "
            "progress and retrieve results - do not wait on this "
            "call, it already returned."
        )
    }


# =====================================================
# PUBLIC ENTRY POINT #2: get_capture_status
#
# Cheap, near-instant call. The MCP client should call this
# repeatedly (e.g. every 15-30s) instead of making one giant
# blocking call. Each individual call here returns fast, so it
# never risks the client-side tool-call timeout, no matter how
# long the underlying capture takes in total.
# =====================================================

async def get_capture_status(job_id: str, wait_seconds: int = 25):

    """
    Bounded long-poll: if the job is still running, wait up to
    `wait_seconds` (checking every 2s) for it to finish before
    returning, instead of returning "still capturing" instantly.
    This cuts down the number of round-trips needed for long
    captures (e.g. ~12-15 calls -> ~2-3 calls for a 5-min capture)
    while staying comfortably under any client-side tool-call
    timeout (observed ~4 min).
    """

    poll_interval = 2
    waited = 0

    while True:

        job = get_job(job_id)

        if job is None:

            return {

                "status": "not_found",

                "message": f"No capture job found with id '{job_id}'."
            }

        # Stop waiting once the job leaves the "in progress" states
        if job["status"] not in ("pending", "capturing", "analyzing"):

            return job

        if waited >= wait_seconds:

            return job

        await asyncio.sleep(poll_interval)

        waited += poll_interval


# =====================================================
# INTERNAL: _run_capture_job
#
# This is where the actual long-running work happens. It runs as
# a detached background task - nothing is awaiting it from the
# MCP tool-call side, so it is free to take as long as it needs
# (5 min, 10 min, whatever `duration` is) without ever tripping a
# client-side request timeout. All progress/results are written
# into the job store, which get_capture_status reads from.
# =====================================================

async def _run_capture_job(
    job_id: str,
    matched_interface: str,
    interface_id: str,
    duration: int,
    capture_filter: str,
    save_capture: bool
):

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    temp_pcap = os.path.join(
        settings.CAPTURE_DIR,
        f"temp_capture_{timestamp}.pcapng"
    )

    capture_cmd = [

        settings.TSHARK_PATH,

        "-i",
        interface_id,

        "-a",
        f"duration:{duration}",

        "-w",
        temp_pcap
    ]

    if capture_filter:

        capture_cmd.extend([
            "-f",
            capture_filter
        ])

    capture_timeout = duration + settings.CAPTURE_TIMEOUT_BUFFER

    # -------------------------------------------------
    # Run Capture
    # -------------------------------------------------

    try:

        await run_tshark(capture_cmd, timeout=capture_timeout)

    except RuntimeError as e:

        if not os.path.exists(temp_pcap):

            update_job(
                job_id,
                status="error",
                error=(
                    f"Live capture on interface '{matched_interface}' "
                    f"did not complete: {e}"
                )
            )

            return

    # Arm cleanup immediately, same reasoning as before: protects
    # against orphaned files if anything below fails.
    schedule_cleanup(
        temp_pcap,
        settings.CAPTURE_CLEANUP_TIMEOUT
    )

    update_job(
        job_id,
        status="analyzing",
        progress={
            "elapsed_seconds": duration,
            "total_seconds": duration
        }
    )

    # -------------------------------------------------
    # Analyze Capture
    # -------------------------------------------------

    analysis_cmd = [

        settings.TSHARK_PATH,

        "-r",
        temp_pcap,

        "-T",
        "json"
    ]

    try:

        output = await run_tshark(analysis_cmd)

    except RuntimeError as e:

        update_job(
            job_id,
            status="error",
            error=(
                "Failed to analyze the captured traffic "
                f"(tshark timed out or failed while reading the "
                f"capture file): {e}"
            ),
            result={
                "temporary_capture": temp_pcap,
                "cleanup_timeout_seconds": settings.CAPTURE_CLEANUP_TIMEOUT
            }
        )

        return

    try:

        packets = json.loads(output)

    except Exception as e:

        update_job(
            job_id,
            status="error",
            error=f"Failed to parse tshark JSON output: {e}",
            result={
                "temporary_capture": temp_pcap,
                "cleanup_timeout_seconds": settings.CAPTURE_CLEANUP_TIMEOUT
            }
        )

        return

    # -------------------------------------------------
    # Dynamic Analysis (unchanged from original)
    # -------------------------------------------------

    protocol_counter = {}
    conversations = {}
    endpoints = {}
    total_packets = 0
    total_bytes = 0

    for packet in packets:

        total_packets += 1

        layers = packet.get("_source", {}).get("layers", {})

        frame_layer = layers.get("frame", {})

        try:

            frame_len = int(frame_layer.get("frame.len", 0))

            total_bytes += frame_len

        except Exception:

            pass

        frame_protocols = frame_layer.get("frame.protocols", "")

        for proto in frame_protocols.split(":"):

            proto = proto.lower().strip()

            if proto:

                protocol_counter[proto] = protocol_counter.get(proto, 0) + 1

        ip_layer = layers.get("ip")
        ipv6_layer = layers.get("ipv6")

        src = None
        dst = None

        if ip_layer:

            src = ip_layer.get("ip.src")
            dst = ip_layer.get("ip.dst")

        elif ipv6_layer:

            src = ipv6_layer.get("ipv6.src")
            dst = ipv6_layer.get("ipv6.dst")

        if src and dst:

            key = f"{src} -> {dst}"

            conversations[key] = conversations.get(key, 0) + 1

            endpoints[src] = endpoints.get(src, 0) + 1
            endpoints[dst] = endpoints.get(dst, 0) + 1

    top_conversations = sorted(
        conversations.items(), key=lambda x: x[1], reverse=True
    )[:10]

    top_endpoints = sorted(
        endpoints.items(), key=lambda x: x[1], reverse=True
    )[:10]

    analysis_metadata = {

        "unique_protocols": list(protocol_counter.keys()),

        "protocol_counts": protocol_counter,

        "conversation_count": len(conversations),

        "endpoint_count": len(endpoints),

        "top_conversations": top_conversations,

        "top_endpoints": top_endpoints,

        "total_packets": total_packets,

        "total_bytes": total_bytes,

        "capture_duration": duration
    }

    # -------------------------------------------------
    # Save Capture If Requested
    # -------------------------------------------------

    if save_capture:

        final_pcap = os.path.join(
            settings.CAPTURE_DIR,
            f"live_capture_{timestamp}.pcapng"
        )

        cancel_cleanup(temp_pcap)

        os.rename(temp_pcap, final_pcap)

        update_job(
            job_id,
            status="completed",
            result={

                "status": "success",

                "capture_saved": True,

                "saved_capture": final_pcap,

                "interface": matched_interface,

                "analysis_metadata": analysis_metadata
            }
        )

        return

    # -------------------------------------------------
    # Ask User Whether To Save
    # -------------------------------------------------

    update_job(
        job_id,
        status="user_input_required",
        result={

            "status": "user_input_required",

            "message": (
                "Live capture analysis completed. "
                "Do you want to save this capture? "
                f"If not discarded or saved within "
                f"{settings.CAPTURE_CLEANUP_TIMEOUT} seconds, "
                "it will be automatically deleted."
            ),

            "capture_saved": False,

            "temporary_capture": temp_pcap,

            "interface": matched_interface,

            "analysis_metadata": analysis_metadata,

            "cleanup_timeout_seconds": settings.CAPTURE_CLEANUP_TIMEOUT,

            "save_options": [

                "yes",
                "no",
                "discard",
                "dig deeper",
                "analyze further",
                "remove this capture",
                "delete this capture"
            ]
        }
    )