from fastmcp import FastMCP

from app.tools.discovery import discover_protocols
from app.tools.packets import query_packets
from app.tools.conversations import analyze_conversations
from app.tools.streams import inspect_stream
from app.tools.statistics import protocol_statistics
from app.tools.behavior import behavioral_analysis
from app.tools.live_capture import live_capture
from app.tools.interfaces import list_interfaces
from app.tools.save_capture import save_capture

from app.resources.references import NETWORK_REFERENCE
from app.prompts.prompts import SYSTEM_PROMPT


mcp = FastMCP("Wireshark MCP")


@mcp.tool()
async def get_protocols(pcap_path: str):
    return await discover_protocols(pcap_path)


@mcp.tool()
async def search_packets(
    pcap_path: str,
    fields: list,
    display_filter: str = None,
    limit: int = 100
):
    return await query_packets(
        pcap_path,
        fields,
        display_filter,
        limit
    )


@mcp.tool()
async def get_conversations(
    pcap_path: str,
    conversation_type: str = "ip"
):
    return await analyze_conversations(
        pcap_path,
        conversation_type
    )


@mcp.tool()
async def follow_stream(
    pcap_path: str,
    stream_type: str,
    stream_id: int
):
    return await inspect_stream(
        pcap_path,
        stream_type,
        stream_id
    )


@mcp.tool()
async def get_statistics(pcap_path: str):
    return await protocol_statistics(pcap_path)


@mcp.tool()
async def analyze_behavior(pcap_path: str):
    return await behavioral_analysis(pcap_path)


@mcp.tool()
async def list_interfaces():
    return await list_interfaces()


@mcp.tool()
async def capture_live(
    interface: str = None,
    duration: int = 10,
    capture_filter: str = None
):

    return await live_capture(
        interface,
        duration,
        capture_filter
    )


@mcp.tool()
async def save_live_capture(
    temporary_capture: str
):
    return await save_capture(
        temporary_capture
    )


@mcp.resource("reference://network")
def network_reference():
    return NETWORK_REFERENCE


@mcp.prompt()
def system_prompt():
    return SYSTEM_PROMPT