from fastmcp import FastMCP

from app.tools.discovery import discover_protocols
from app.tools.packets import query_packets
from app.tools.conversations import analyze_conversations
from app.tools.streams import inspect_stream
from app.tools.statistics import protocol_statistics
from app.tools.behavior import behavioral_analysis
from app.tools.live_capture import start_live_capture, get_capture_status
from app.tools.interfaces import list_interfaces as list_interfaces_impl
from app.tools.save_capture import save_capture
from app.tools.discard_capture import discard_capture
from app.utils.cleanup import sweep_stale_temp_captures

from app.resources.references import NETWORK_REFERENCE
from app.prompts.prompts import SYSTEM_PROMPT


mcp = FastMCP("Wireshark MCP")


@mcp.tool()
async def get_protocols(
    pcap_path: str,
    offset: int = 0,
    max_chars: int = 200_000
):
    """
    Discover which network protocols appear in a packet capture file
    and how many frames/bytes each protocol accounts for.

    This tool reads the file directly from the filesystem of the
    machine running this Wireshark MCP server (e.g. a local Windows
    or Linux path such as "C:\\traffic.pcapng" or
    "/home/user/traffic.pcapng"). Do NOT ask the user to upload the
    file to you first - call this tool directly with the path they
    gave you, exactly as they gave it.

    Result is paginated to stay under transport payload limits: if
    "truncated": true, call again with offset=next_offset.

    Args:
        pcap_path: Absolute path to the .pcap/.pcapng file on the
            MCP server's host machine.
        offset: Character offset to resume from (for pagination).
        max_chars: Max characters to return in this call.
    """
    return await discover_protocols(pcap_path, offset, max_chars)


@mcp.tool()
async def search_packets(
    pcap_path: str,
    fields: list,
    display_filter: str = None,
    limit: int = 100
):
    """
    Query specific fields from packets in a capture file, optionally
    filtered with a Wireshark display filter (e.g. "http",
    "ip.addr==10.0.0.1", "tcp.port==443").

    Reads the file directly from the MCP server's own host machine -
    never ask the user to upload the pcap; call this tool with the
    path they provided.

    Args:
        pcap_path: Absolute path to the .pcap/.pcapng file.
        fields: List of Wireshark field names to extract, e.g.
            ["frame.number", "ip.src", "http.request.method"].
        display_filter: Optional Wireshark display filter string.
        limit: Max number of matching rows to return.
    """
    return await query_packets(
        pcap_path,
        fields,
        display_filter,
        limit
    )


@mcp.tool()
async def get_conversations(
    pcap_path: str,
    conversation_type: str = "ip",
    offset: int = 0,
    max_chars: int = 200_000
):
    """
    Summarize conversations (talker pairs) in a capture file, e.g.
    which IP addresses or TCP endpoints talked to each other and how
    much traffic each conversation carried.

    Reads the file directly from the MCP server's own host machine -
    never ask the user to upload the pcap; call this tool with the
    path they provided.

    Result is paginated to stay under transport payload limits: if
    "truncated": true, call again with offset=next_offset.

    Args:
        pcap_path: Absolute path to the .pcap/.pcapng file.
        conversation_type: "ip", "tcp", or "udp".
        offset: Character offset to resume from (for pagination).
        max_chars: Max characters to return in this call.
    """
    return await analyze_conversations(
        pcap_path,
        conversation_type,
        offset,
        max_chars
    )


@mcp.tool()
async def follow_stream(
    pcap_path: str,
    stream_type: str,
    stream_id: int,
    offset: int = 0,
    max_chars: int = 300_000
):
    """
    Reassemble and return the raw application-layer content of a
    single TCP/UDP stream (e.g. an HTTP request/response, an FTP
    session), for inspecting plaintext data, credentials, or payloads.

    Reads the file directly from the MCP server's own host machine -
    never ask the user to upload the pcap; call this tool with the
    path they provided.

    Large streams are paginated: if the result has "truncated": true,
    call this tool again with offset set to the returned
    "next_offset" to fetch the remaining content.

    Args:
        pcap_path: Absolute path to the .pcap/.pcapng file.
        stream_type: "tcp" or "udp".
        stream_id: The stream index (see tcp.stream / udp.stream).
        offset: Character offset to resume from (for pagination).
        max_chars: Max characters to return in this call.
    """
    return await inspect_stream(
        pcap_path,
        stream_type,
        stream_id,
        offset,
        max_chars
    )


@mcp.tool()
async def get_statistics(
    pcap_path: str,
    offset: int = 0,
    max_chars: int = 200_000
):
    """
    Compute overall protocol statistics for a capture file (packet
    counts, byte counts, protocol hierarchy breakdown).

    Reads the file directly from the MCP server's own host machine -
    never ask the user to upload the pcap; call this tool with the
    path they provided.

    Result is paginated to stay under transport payload limits: if
    "truncated": true, call again with offset=next_offset.

    Args:
        pcap_path: Absolute path to the .pcap/.pcapng file.
        offset: Character offset to resume from (for pagination).
        max_chars: Max characters to return in this call.
    """
    return await protocol_statistics(pcap_path, offset, max_chars)


@mcp.tool()
async def analyze_behavior(pcap_path: str):
    """
    Run automated security/behavioral analysis on a capture file:
    detects plaintext credential exposure (login forms, Basic/Bearer
    auth headers, etc.) across every non-TLS-encrypted TCP stream, and
    flags insecure protocols in use (HTTP, FTP, Telnet, etc).

    Call this whenever the user asks anything like "is there anything
    suspicious", "any security risk", or "anything wrong with this
    traffic" - do not try to manually re-derive this from raw packets.

    Reads the file directly from the MCP server's own host machine -
    never ask the user to upload the pcap; call this tool with the
    path they provided.

    Args:
        pcap_path: Absolute path to the .pcap/.pcapng file.
    """
    return await behavioral_analysis(pcap_path)


@mcp.tool()
async def list_interfaces():
    """
    List the network interfaces available for live capture on the
    machine running this Wireshark MCP server (e.g. the user's own
    Windows/Linux/Mac machine, not Claude's environment).
    """
    return await list_interfaces_impl()


@mcp.tool()
async def capture_live(
    interface: str = None,
    duration: int = 10,
    capture_filter: str = None,
    save_capture: bool = False
):
    """
    Start a live packet capture on an interface of the machine running
    this Wireshark MCP server, for the given duration.

    This does NOT block until the capture finishes - it starts the
    capture in the background and returns almost immediately with a
    "job_id". This matters for anything longer than ~30-60 seconds:
    a single tool call that blocked for the full capture duration
    (e.g. 5 minutes) can exceed the client's own request timeout and
    make the server look unresponsive, even though the capture itself
    would have completed fine.

    After calling this, call check_capture_status repeatedly (e.g.
    every 15-30 seconds) with the returned job_id until status is
    "completed", "user_input_required", or "error".

    The captured file is always a temporary file first - it is never
    saved permanently unless save_capture=True was passed here, or an
    explicit follow-up call to save_live_capture is made once the job
    completes.

    Args:
        interface: Interface name/number (call list_interfaces if
            unknown; omitting this returns the available interfaces
            for the user to choose from).
        duration: Capture duration in seconds.
        capture_filter: Optional BPF capture filter, e.g. "tcp port 80".
        save_capture: If True, automatically save the capture
            permanently once it completes, skipping the
            save/discard prompt.
    """
    return await start_live_capture(
        interface,
        duration,
        capture_filter,
        save_capture
    )


@mcp.tool()
async def check_capture_status(job_id: str, wait_seconds: int = 25):
    """
    Check the status/result of a live capture previously started with
    capture_live. This call will wait up to `wait_seconds` for the
    job to finish before returning (long-poll), so for a long
    capture you generally just need to call this a handful of times,
    not once every couple seconds. Keep calling it again immediately
    if the returned status is still "capturing" or "analyzing".

    Possible "status" values: "capturing", "analyzing", "completed",
    "user_input_required" (analysis done, ask the user whether to
    save/discard), "error", or "not_found" (invalid/expired job_id).

    Args:
        job_id: The job_id returned by capture_live.
        wait_seconds: Max seconds to wait/poll internally before
            returning if the job is still in progress. Keep this
            comfortably below any client-side tool-call timeout
            (e.g. 25-30s is safe even if that timeout is ~4 min).
    """
    return await get_capture_status(job_id, wait_seconds)


@mcp.tool()
async def save_live_capture(
    temporary_capture: str
):
    """
    Permanently save a temporary capture file (returned once a
    capture_live job completes) so it survives the auto-discard
    cleanup timeout.

    Args:
        temporary_capture: The exact "temporary_capture" path
            returned in the completed capture job's result.
    """
    return await save_capture(
        temporary_capture
    )


@mcp.tool()
async def discard_live_capture(
    temporary_capture: str
):
    """
    Immediately delete a temporary capture file (returned once a
    capture_live job completes) instead of waiting for the
    auto-discard timeout.

    Args:
        temporary_capture: The exact "temporary_capture" path
            returned in the completed capture job's result.
    """
    return await discard_capture(temporary_capture)


# Clean up any temp_capture_* files left behind by a previous
# server run (e.g. the process was killed before its in-memory
# cleanup timer could fire).
sweep_stale_temp_captures()


@mcp.resource("reference://network")
def network_reference():
    return NETWORK_REFERENCE


@mcp.prompt()
def system_prompt():
    return SYSTEM_PROMPT