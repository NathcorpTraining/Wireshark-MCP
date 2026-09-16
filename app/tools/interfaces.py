from app.utils.tshark import run_tshark
from app.config import settings


async def list_interfaces():

    cmd = [
        settings.TSHARK_PATH,
        "-D"
    ]

    output = await run_tshark(cmd)

    interfaces = []

    for line in output.splitlines():

        if "." in line:
            interfaces.append(line.strip())

    return {
        "interfaces": interfaces
    }