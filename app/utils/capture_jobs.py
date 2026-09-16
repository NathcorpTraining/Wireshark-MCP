import uuid
from datetime import datetime

# ---------------------------------------------------
# In-memory job registry
#
# NOTE: This lives in process memory only. If your MCP server
# process restarts, all job state is lost (any in-progress
# capture's job record disappears, though the underlying tshark
# process/tempfile may still be on disk - that's a separate
# concern from cleanup.py). For a single local desktop MCP
# server this is fine; if you ever run multiple server workers/
# processes, this needs to move to a shared store (sqlite, redis,
# etc.) since each worker would otherwise have its own registry.
# ---------------------------------------------------

_jobs = {}


def create_job():

    job_id = str(uuid.uuid4())

    _jobs[job_id] = {

        "job_id": job_id,

        "status": "pending",  # pending -> capturing -> analyzing -> completed | error | user_input_required

        "created_at": datetime.now().isoformat(),

        "updated_at": datetime.now().isoformat(),

        "progress": None,

        "result": None,

        "error": None
    }

    return job_id


def update_job(job_id: str, **fields):

    job = _jobs.get(job_id)

    if job is None:
        return None

    job.update(fields)

    job["updated_at"] = datetime.now().isoformat()

    return job


def get_job(job_id: str):

    return _jobs.get(job_id)


def list_jobs():

    return list(_jobs.values())