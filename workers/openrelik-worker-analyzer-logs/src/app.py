# Copyright 2025 Google LLC
# ... (license header) ...

import os
import redis
from celery.app import Celery
from openrelik_common import telemetry
from openrelik_worker_common.debug_utils import start_debugger

telemetry.setup_telemetry('openrelik-worker-analyzer-logs')

if os.getenv("OPENRELIK_PYDEBUG") == "1":
    start_debugger()

REDIS_URL = os.getenv("REDIS_URL") or "redis://localhost:6379/0"

# CHANGE 1: Explicitly name the Celery app to match the worker name
# CHANGE 2: Ensure the include points to the module relative to your working directory
celery = Celery(
    "openrelik-worker-analyzer-logs", 
    broker=REDIS_URL, 
    backend=REDIS_URL, 
    include=["src.tasks"] # Changed from "src.tasks" to "tasks"
)

redis_client = redis.Redis.from_url(REDIS_URL)
telemetry.instrument_celery_app(celery)
