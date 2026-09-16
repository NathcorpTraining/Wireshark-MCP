import base64
import re
from urllib.parse import unquote

from app.utils.tshark import run_tshark
from app.config import settings


# Substrings checked against form/query parameter *names* (not exact
# words), so custom field names like "tfUPass" or "j_username" are
# still caught because they contain "pass" / "uname". This is the
# fallback for arbitrary/custom web-form fields that have no known
# protocol dissector.
CREDENTIAL_KEY_HINTS = [
    "user", "uname", "login", "email", "pass", "pwd",
    "token", "secret", "auth", "session", "apikey",
    "api_key", "otp", "pin", "credential"
]

INSECURE_PROTOCOLS = {
    "ftp": "FTP (unencrypted file transfer)",
    "telnet": "Telnet (unencrypted remote shell)",
    "http": "HTTP (unencrypted web traffic)",
    "tftp": "TFTP (unencrypted file transfer)",
    "snmp": "SNMP (often uses default/plaintext community strings)",
    "pop": "POP (often unencrypted mail)",
    "imap": "IMAP (often unencrypted mail)",
    "smtp": "SMTP (often unencrypted mail)",
    "ldap": "LDAP (often uses unencrypted simple bind credentials)"
}


async def _run_field_query(pcap_path: str, display_filter: str, fields: list):
    """
    Run a tshark -T fields query scoped to a display filter. Returns
    a list of rows (each a list of field values), or [] on failure
    (e.g. the protocol just isn't present in this capture).
    """

    cmd = [
        settings.TSHARK_PATH,
        "-r", pcap_path,
        "-Y", display_filter,
        "-T", "fields",
        "-E", "separator=|"
    ]

    for field in fields:
        cmd.extend(["-e", field])

    try:
        output = await run_tshark(cmd)
    except Exception:
        return []

    rows = []

    for line in output.splitlines():

        line = line.strip()

        if not line:
            continue

        rows.append(line.split("|"))

    return rows


async def _protocol_native_credentials(pcap_path: str):
    """
    Use tshark's own protocol dissectors to pull out credentials from
    protocols that carry them in a structured (often binary/BER
    encoded) way that a plaintext regex scan can't reliably parse -
    most notably LDAP simple bind, but also FTP/POP/IMAP command
    verbs and HTTP Basic Auth.
    """

    findings = []

    # ---- LDAP simple bind (DN + password are separate BER fields,
    # not "key=value" text - a raw-text regex scan can't see these) ----
    for row in await _run_field_query(
        pcap_path,
        "ldap.simple and ldap.simple != \"\"",
        ["frame.number", "ldap.name", "ldap.simple"]
    ):
        frame_no, dn, password = (row + ["", "", ""])[:3]

        if password:
            findings.append({
                "protocol": "LDAP",
                "frame": frame_no,
                "field": "ldap.simple (bind password)",
                "value": password,
                "evidence_line": f"bindRequest DN=\"{dn}\" simple=\"{password}\""
            })

    # ---- FTP USER / PASS commands ----
    for row in await _run_field_query(
        pcap_path,
        "ftp.request.command == \"USER\" or ftp.request.command == \"PASS\"",
        ["frame.number", "ftp.request.command", "ftp.request.arg"]
    ):
        frame_no, command, arg = (row + ["", "", ""])[:3]

        if arg:
            findings.append({
                "protocol": "FTP",
                "frame": frame_no,
                "field": f"ftp.request ({command})",
                "value": arg,
                "evidence_line": f"{command} {arg}"
            })

    # ---- POP3 USER / PASS commands ----
    for row in await _run_field_query(
        pcap_path,
        "pop.request.command == \"USER\" or pop.request.command == \"PASS\"",
        ["frame.number", "pop.request.command", "pop.request.parameter"]
    ):
        frame_no, command, arg = (row + ["", "", ""])[:3]

        if arg:
            findings.append({
                "protocol": "POP3",
                "frame": frame_no,
                "field": f"pop.request ({command})",
                "value": arg,
                "evidence_line": f"{command} {arg}"
            })

    # ---- IMAP LOGIN (tshark exposes username/password directly) ----
    for row in await _run_field_query(
        pcap_path,
        "imap.request.username or imap.request.password",
        ["frame.number", "imap.request.username", "imap.request.password"]
    ):
        frame_no, username, password = (row + ["", "", ""])[:3]

        if username or password:
            findings.append({
                "protocol": "IMAP",
                "frame": frame_no,
                "field": "imap.request (LOGIN)",
                "value": f"{username}:{password}",
                "evidence_line": f"LOGIN {username} {password}"
            })

    # ---- HTTP Basic Auth (tshark decodes this for us already) ----
    for row in await _run_field_query(
        pcap_path,
        "http.authbasic",
        ["frame.number", "http.authbasic"]
    ):
        frame_no, decoded = (row + ["", ""])[:2]

        if decoded:
            findings.append({
                "protocol": "HTTP",
                "frame": frame_no,
                "field": "http.authbasic",
                "value": decoded,
                "evidence_line": f"Authorization: Basic (decoded: {decoded})"
            })

    # ---- SNMP community strings (v1/v2c have no encryption at all) ----
    for row in await _run_field_query(
        pcap_path,
        "snmp.community",
        ["frame.number", "snmp.community"]
    ):
        frame_no, community = (row + ["", ""])[:2]

        if community:
            findings.append({
                "protocol": "SNMP",
                "frame": frame_no,
                "field": "snmp.community",
                "value": community,
                "evidence_line": f"community=\"{community}\""
            })

    return findings


def _extract_credentials_from_text(text: str, stream_id: int, source: str):
    """
    Fallback heuristic scan of raw stream text, for arbitrary/custom
    web-form fields and Bearer tokens that have no dedicated tshark
    dissector field to query directly.
    """

    findings = []

    for line in text.splitlines():

        line = line.strip()

        if not line:
            continue

        for pair in re.split(r"[&;]", line):

            if "=" not in pair:
                continue

            key, _, value = pair.partition("=")
            key_lower = key.strip().lower()
            value = value.strip()

            if not value:
                continue

            if any(hint in key_lower for hint in CREDENTIAL_KEY_HINTS):

                findings.append({
                    "protocol": "HTTP (form/query)",
                    "stream_id": stream_id,
                    "source": source,
                    "field": key.strip(),
                    "value": unquote(value)[:100],
                    "evidence_line": line[:200]
                })

        bearer_match = re.search(
            r"Authorization:\s*Bearer\s+([A-Za-z0-9\-_\.]+)",
            line,
            re.IGNORECASE
        )

        if bearer_match:

            findings.append({
                "protocol": "HTTP",
                "stream_id": stream_id,
                "source": source,
                "field": "Authorization: Bearer",
                "value": bearer_match.group(1)[:100],
                "evidence_line": line[:200]
            })

    return findings


async def behavioral_analysis(pcap_path: str, max_streams: int = 200):

    findings = {
        "plaintext_credentials": [],
        "insecure_protocols": {},
        "tls_stream_count": 0,
        "plaintext_stream_count": 0,
        "streams_inspected": 0,
        "notes": []
    }

    # ---------------------------------------------------
    # Insecure protocol usage (from protocol hierarchy)
    # ---------------------------------------------------

    try:

        phs_output = await run_tshark([
            settings.TSHARK_PATH,
            "-r", pcap_path,
            "-q", "-z", "io,phs"
        ])

    except Exception as e:

        phs_output = ""
        findings["notes"].append(
            f"Could not compute protocol hierarchy: {e}"
        )

    for proto_name, label in INSECURE_PROTOCOLS.items():

        if re.search(rf"\b{proto_name}\b", phs_output, re.IGNORECASE):
            findings["insecure_protocols"][proto_name] = label

    # ---------------------------------------------------
    # Protocol-native structured credential extraction
    # (LDAP, FTP, POP3, IMAP, HTTP Basic Auth, SNMP)
    # ---------------------------------------------------

    findings["plaintext_credentials"].extend(
        await _protocol_native_credentials(pcap_path)
    )

    # ---------------------------------------------------
    # Which TCP streams are TLS-encrypted (skip these)
    # ---------------------------------------------------

    tls_streams = set()

    try:

        tls_output = await run_tshark([
            settings.TSHARK_PATH,
            "-r", pcap_path,
            "-Y", "tls",
            "-T", "fields",
            "-e", "tcp.stream"
        ])

        for line in tls_output.splitlines():

            line = line.strip()

            if line.isdigit():
                tls_streams.add(int(line))

    except Exception as e:

        findings["notes"].append(
            f"Could not determine TLS streams: {e}"
        )

    findings["tls_stream_count"] = len(tls_streams)

    # ---------------------------------------------------
    # All TCP stream indices present in the capture
    # ---------------------------------------------------

    all_streams = set()

    try:

        stream_output = await run_tshark([
            settings.TSHARK_PATH,
            "-r", pcap_path,
            "-T", "fields",
            "-e", "tcp.stream"
        ])

        for line in stream_output.splitlines():

            line = line.strip()

            if line.isdigit():
                all_streams.add(int(line))

    except Exception as e:

        findings["notes"].append(
            f"Could not list TCP streams: {e}"
        )

    plaintext_streams = sorted(all_streams - tls_streams)
    findings["plaintext_stream_count"] = len(plaintext_streams)

    if len(plaintext_streams) > max_streams:

        findings["notes"].append(
            f"{len(plaintext_streams)} plaintext streams found; "
            f"only inspecting the first {max_streams} for "
            "credential exposure."
        )
        plaintext_streams = plaintext_streams[:max_streams]

    # ---------------------------------------------------
    # Fallback: follow every plaintext stream's raw text for
    # arbitrary custom web-form fields / Bearer tokens that have
    # no dedicated protocol dissector field to query directly.
    # ---------------------------------------------------

    for stream_id in plaintext_streams:

        try:

            stream_text = await run_tshark([
                settings.TSHARK_PATH,
                "-r", pcap_path,
                "-q", "-z", f"follow,tcp,ascii,{stream_id}"
            ])

        except Exception as e:

            findings["notes"].append(
                f"Failed to follow tcp.stream {stream_id}: {e}"
            )
            continue

        findings["streams_inspected"] += 1

        matches = _extract_credentials_from_text(
            stream_text,
            stream_id,
            source=f"tcp.stream eq {stream_id}"
        )

        findings["plaintext_credentials"].extend(matches)

    # ---------------------------------------------------
    # Summary
    # ---------------------------------------------------

    findings["summary"] = {

        "credentials_found": len(findings["plaintext_credentials"]) > 0,

        "credential_count": len(findings["plaintext_credentials"]),

        "insecure_protocols_found": len(findings["insecure_protocols"]) > 0,

        "message": (
            f"Checked protocol-native credential fields (LDAP, FTP, "
            f"POP3, IMAP, HTTP Basic Auth, SNMP) plus "
            f"{findings['streams_inspected']} plaintext TCP stream(s) "
            f"out of {findings['plaintext_stream_count']} total "
            f"({findings['tls_stream_count']} stream(s) were TLS-encrypted "
            f"and skipped). Found {len(findings['plaintext_credentials'])} "
            f"potential credential exposure(s) and "
            f"{len(findings['insecure_protocols'])} insecure protocol(s) "
            "in use."
        )
    }

    return findings