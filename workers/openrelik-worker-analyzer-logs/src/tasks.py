# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import re
import os
from openrelik_worker_common.file_utils import create_output_file, is_disk_image
from openrelik_worker_common.mount_utils import BlockDevice

from celery import signals
from celery.utils.log import get_task_logger
from openrelik_common import telemetry
from openrelik_worker_common.file_utils import create_output_file
from openrelik_worker_common.reporting import Priority, Report
from openrelik_worker_common.task_utils import create_task_result, get_input_files

from .app import celery
from .logger import log_root
from .ssh_analyzer import LinuxSSHAnalysisTask

# Task name used to register and route the task to the correct queue.
TASK_NAME = "openrelik-worker-analyzer-logs.tasks.ssh_analyzer"

# Task metadata for registration in the core system.
TASK_METADATA = {
    "display_name": "SSH login analyzer",
    "description": "Search for suspicious SSH login events in system logs",
    # Configuration that will be rendered as a web for in the UI, and any data entered
    # by the user will be available to the task function when executing (task_config).
    "task_config": [
        {
            "name": "log_year",
            "label": "Log year",
            "description": "Specify log year for SSH events, in case it's not captured by syslog. Otherwise it will be guessed based on the last SSH event and current date/time.",
            "type": "text",  # Types supported: text, textarea, checkbox
            "required": False,
        },
    ],
}

logger = log_root.get_logger(__name__, get_task_logger(__name__))


@signals.task_prerun.connect
def on_task_prerun(sender, task_id, task, args, kwargs, **_):
    log_root.bind(
        task_id=task_id,
        task_name=task.name,
        worker_name=TASK_METADATA.get("display_name"),
    )


@celery.task(bind=True, name=TASK_NAME, metadata=TASK_METADATA)
def run_ssh_analyzer(
    self,
    pipe_result: str = None,
    input_files: list = None,
    output_path: str = None,
    workflow_id: str = None,
    task_config: dict = None,
) -> str:
    """Run <REPLACE_WITH_COMMAND> on input files.

    Args:
        pipe_result: Base64-encoded result from the previous Celery task, if any.
        input_files: List of input file dictionaries (unused if pipe_result exists).
        output_path: Path to the output directory.
        workflow_id: ID of the workflow.
        task_config: User configuration for the task.

    Returns:
        Base64-encoded dictionary containing task results.
    """
    log_root.bind(workflow_id=workflow_id)
    logger.info(f"Starting {TASK_NAME} for workflow {workflow_id}")

    input_files = get_input_files(pipe_result, input_files or [])
    output_files = []

    telemetry.add_attribute_to_current_span("input_files", input_files)
    telemetry.add_attribute_to_current_span("task_config", task_config)
    telemetry.add_attribute_to_current_span("workflow_id", workflow_id)

    task_report = Report("SSH log analyzer report")
    summary_section = task_report.add_section()

    try:
        log_year = int(task_config.get("log_year"))
    except (TypeError, ValueError):
        log_year = None

    ssh_analysis_task = LinuxSSHAnalysisTask(log_year=log_year)
    analyzer_output_priority = Priority.LOW

    # Indicate task progress start.
    self.send_event("task-progress")

    df = ssh_analysis_task.read_logs(input_files=input_files)
    if df.empty:
        summary_section.add_paragraph("No SSH authentication events in input files.")
    else:
        # 01. Brute Force Analyzer
        (result_priority, result_summary, result_markdown) = (
            ssh_analysis_task.brute_force_analysis(df)
        )
        if result_priority > analyzer_output_priority:
            task_report.priority = result_priority
        logger.debug(f"Report priority: {result_priority}")

        summary_section.add_paragraph(result_markdown)

        output_file = create_output_file(
            output_path,
            display_name="linux_ssh_analysis",
            extension=".md",
            data_type="openrelik:ssh:report",
        )
        with open(output_file.path, "w") as outfile:
            outfile.write(result_markdown)

        output_files.append(output_file.to_dict())

    return create_task_result(
        output_files=output_files,
        workflow_id=workflow_id,
        task_report=task_report.to_dict(),
        meta={},
    )


# --- NEW: Log Discovery Function ---
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

LOG_PATTERN_REGEX = re.compile(
    r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}|'  
    r'(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|'
    r'\[(?:DEBUG|INFO|WARNING|ERROR|CRITICAL|FATAL|NOTICE)\]|'
    r'^(?:DEBUG|INFO|WARNING|ERROR|CRITICAL|FATAL|NOTICE):',
    re.IGNORECASE
)

def is_binary(filepath):
    try:
        with open(filepath, 'rb') as f:
            return b'\0' in f.read(1024)
    except IOError:
        return True

@celery.task(bind=True, name=TASK_NAME_DISCOVERY, metadata=TASK_METADATA_DISCOVERY)
def run_log_discovery(
    self,
    pipe_result: str = None,
    input_files: list = None,
    output_path: str = None,
    workflow_id: str = None,
    task_config: dict = None,
) -> str:
    """Recursively identifies logs, mounts disks, and outputs a report."""
    log_root.bind(workflow_id=workflow_id)
    input_files = get_input_files(pipe_result, input_files or [])
    output_files = []
    
    threshold = float(task_config.get("threshold") or 0.15)
    mount_disk_images = task_config.get("mount_disk_images", True)
    
    discovered_data = [] 
    disks_mounted = [] 
    
    def check_file(file_path, formatted_path, path_list):
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
                path_list.append(formatted_path)
        except Exception as e:
            logger.warning(f"Failed to read {file_path}: {e}")

    try:
        for input_file in input_files:
            path = input_file.get('path')
            base_name = input_file.get('display_name', path)
            evidence_id = input_file.get('uuid', input_file.get('id', 'UNKNOWN_UUID'))
            
            current_evidence = {
                'id': evidence_id,
                'name': base_name,
                'paths': []
            }

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
                            formatted_path = "/" + os.path.relpath(full_path, mountpoint)
                            check_file(full_path, formatted_path, current_evidence['paths'])

            elif os.path.isdir(path):
                for root, dirs, files in os.walk(path):
                    for filename in files:
                        full_path = os.path.join(root, filename)
                        formatted_path = "/" + os.path.relpath(full_path, path)
                        check_file(full_path, formatted_path, current_evidence['paths'])
                        
            elif os.path.isfile(path):
                check_file(path, "/" + os.path.basename(path), current_evidence['paths'])

            if current_evidence['paths']:
                discovered_data.append(current_evidence)

    finally:
        for blockdevice in disks_mounted:
            if blockdevice:
                logger.info(f"Unmounting image {blockdevice.image_path}")
                blockdevice.umount()

    total_logs = 0
    if discovered_data:
        report_file = create_output_file(
            output_path,
            display_name="potential_logs_report.txt",
            data_type="openrelik:report"
        )
        with open(report_file.path, 'w') as f:
            for data in discovered_data:
                f.write(f"Evidence ID: {data['id']}\n")
                f.write(f"Evidence Name: {data['name']}\n\n")
                f.write("Potential Log Files Discovered:\n")
                f.write("-" * 50 + "\n")
                
                for p in sorted(data['paths']):
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
