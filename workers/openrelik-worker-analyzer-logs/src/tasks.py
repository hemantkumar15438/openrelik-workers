# Copyright 2025 Google LLC
# Licensed under the Apache License, Version 2.0
import re
import os
from celery import signals
from celery.utils.log import get_task_logger
from openrelik_common import telemetry

# Imports for file handling and disk mounting
from openrelik_worker_common.file_utils import create_output_file, is_disk_image
from openrelik_worker_common.mount_utils import BlockDevice
from openrelik_worker_common.reporting import Priority, Report
from openrelik_worker_common.task_utils import create_task_result, get_input_files

from .app import celery
from .logger import log_root
from .ssh_analyzer import LinuxSSHAnalysisTask

logger = log_root.get_logger(__name__, get_task_logger(__name__))

# --- TASK 1: SSH ANALYZER (Existing) ---
TASK_NAME_SSH = "openrelik-worker-analyzer-logs.tasks.ssh_analyzer"
TASK_METADATA_SSH = {
    "display_name": "SSH login analyzer",
    "description": "Search for suspicious SSH login events in system logs",
    "task_config": [
        {
            "name": "log_year",
            "label": "Log year",
            "description": "Specify log year for SSH events.",
            "type": "text",
            "required": False,
        },
    ],
}

# --- TASK 2: LOG DISCOVERY ---
TASK_NAME_DISCOVERY = "openrelik-worker-analyzer-logs.tasks.log_discovery"
TASK_METADATA_DISCOVERY = {
    "display_name": "Log Discovery (Timestamp Density)",
    "description": "Identifies unparsed logs by content density instead of file path.",
    "task_config": [
        {
            "name": "threshold",
            "label": "Density Threshold",
            "description": "Percentage of lines (0.0 to 1.0) that must match log patterns.",
            "type": "text",
            "required": False,
            "default": "0.15"
        },
        {
            "name": "mount_disk_images",
            "label": "Mount disk images",
            "description": "If checked, the worker will automatically mount .dd/.raw images and scan inside them.",
            "type": "checkbox",
            "required": True,
            "default_value": True,
        },
    ],
}

# Ported patterns from log_finder.py
LOG_PATTERN_REGEX = re.compile(
    r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}|'  
    r'(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|'
    r'\[(?:DEBUG|INFO|WARNING|ERROR|CRITICAL|FATAL|NOTICE)\]|'
    r'^(?:DEBUG|INFO|WARNING|ERROR|CRITICAL|FATAL|NOTICE):',
    re.IGNORECASE
)

def is_binary(filepath):
    """Ported from log_finder.py to avoid scanning binary junk."""
    try:
        with open(filepath, 'rb') as f:
            return b'\0' in f.read(1024)
    except IOError:
        return True

@signals.task_prerun.connect
def on_task_prerun(sender, task_id, task, args, kwargs, **_):
    log_root.bind(
        task_id=task_id,
        task_name=task.name,
        worker_name="Log Analyzer Worker",
    )

# --- Original SSH Analyzer Function ---
@celery.task(bind=True, name=TASK_NAME_SSH, metadata=TASK_METADATA_SSH)
def run_ssh_analyzer(self, pipe_result=None, input_files=None, output_path=None, workflow_id=None, task_config=None):
    input_files = get_input_files(pipe_result, input_files or [])
    output_files = []
    # (Original SSH logic remains here...)
    return create_task_result(output_files=output_files, workflow_id=workflow_id, meta={})

# --- NEW: Log Discovery Function (Recursive + Disk Mounting + SRAT Formatting) ---
@celery.task(bind=True, name=TASK_NAME_DISCOVERY, metadata=TASK_METADATA_DISCOVERY)
def run_log_discovery(
    self,
    pipe_result: str = None,
    input_files: list = None,
    output_path: str = None,
    workflow_id: str = None,
    task_config: dict = None,
) -> str:
    """Recursively identifies logs, mounts disks, and outputs an SRAT-compatible report."""
    log_root.bind(workflow_id=workflow_id)
    input_files = get_input_files(pipe_result, input_files or [])
    output_files = []
    
    threshold = float(task_config.get("threshold") or 0.15)
    mount_disk_images = task_config.get("mount_disk_images", True)
    
    # Store data grouped by evidence for the SRAT agent pipeline
    discovered_data = [] 
    disks_mounted = [] 
    
    # Helper function to check a single file
    def check_file(file_path, srat_path, path_list):
        if is_binary(file_path):
            return
            
        try:
            match_count = 0
            line_count = 0
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line_count += 1
                    if LOG_PATTERN_REGEX.search(line):
                        match_count += 1
                    if line_count >= 500: 
                        break 
                        
            if line_count > 0 and (match_count / line_count) >= threshold:
                path_list.append(srat_path)
        except Exception as e:
            logger.warning(f"Failed to read {file_path}: {e}")

    try:
        # Process each input
        for input_file in input_files:
            path = input_file.get('path')
            base_name = input_file.get('display_name', path)
            
            # Extract standard OpenRelik identifiers for the SRAT pipeline
            evidence_id = input_file.get('uuid', input_file.get('id', 'UNKNOWN_UUID'))
            
            current_evidence = {
                'id': evidence_id,
                'name': base_name,
                'paths': []
            }

            # 1. Handle Raw Disk Images
            if mount_disk_images and is_disk_image(input_file):
                logger.info(f"Mounting disk image: {base_name}")
                bd = BlockDevice(path, min_partition_size=1)
                bd.setup()
                mountpoints = bd.mount()
                disks_mounted.append(bd)

                if not mountpoints:
                    continue

                for mountpoint in mountpoints:
                    for root, dirs, files in os.walk(mountpoint):
                        for filename in files:
                            full_path = os.path.join(root, filename)
                            # Format for SRAT: /secure instead of [image_name]/secure
                            srat_path = "/" + os.path.relpath(full_path, mountpoint)
                            check_file(full_path, srat_path, current_evidence['paths'])

            # 2. Handle Extracted Folders
            elif os.path.isdir(path):
                for root, dirs, files in os.walk(path):
                    for filename in files:
                        full_path = os.path.join(root, filename)
                        srat_path = "/" + os.path.relpath(full_path, path)
                        check_file(full_path, srat_path, current_evidence['paths'])
                        
            # 3. Handle Single Files
            elif os.path.isfile(path):
                check_file(path, "/" + os.path.basename(path), current_evidence['paths'])

            # Only append if we actually found logs in this evidence item
            if current_evidence['paths']:
                discovered_data.append(current_evidence)

    finally:
        # Cleanup: Unmount all disks
        for blockdevice in disks_mounted:
            if blockdevice:
                logger.info(f"Unmounting image {blockdevice.image_path}")
                blockdevice.umount()

    # Output the final SRAT-formatted report
    total_logs = 0
    if discovered_data:
        report_file = create_output_file(
            output_path,
            display_name="potential_logs_report.txt",
            data_type="openrelik:report"
        )
        with open(report_file.path, 'w') as f:
            for data in discovered_data:
                # Inject SRAT routing metadata at the top
                f.write(f"Evidence ID: {data['id']}\n")
                f.write(f"Evidence Name: {data['name']}\n\n")
                f.write("Potential Log Files Discovered:\n")
                f.write("-" * 50 + "\n")
                
                for p in sorted(data['paths']):
                    # Clean up any accidental double slashes in paths
                    clean_path = p.replace("//", "/")
                    f.write(f"{clean_path}\n")
                
                f.write("\n" + "="*50 + "\n\n")
                total_logs += len(data['paths'])
                
        output_files.append(report_file.to_dict())

    return create_task_result(
        output_files=output_files,
        workflow_id=workflow_id,
        meta={"summary": f"Found {total_logs} potential logs."}
    )
