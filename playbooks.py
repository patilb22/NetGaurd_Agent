"""Validated dry-run and human-approved mitigation playbooks.

Actual host changes require both a graph approval and
``NETGUARD_ENABLE_PLAYBOOK_EXECUTION=1``. Commands use argument lists with
``shell=False``; state-changing rules receive a unique marker and a scheduled
rollback.
"""

from __future__ import annotations

import ipaddress
import os
import platform
import re
import shutil
import subprocess
import threading
import uuid
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone

from apscheduler.schedulers.background import BackgroundScheduler

from src.netguard.policies import ThreatType, select_playbook

_EXECUTION_ENV = "NETGUARD_ENABLE_PLAYBOOK_EXECUTION"
_ROLLBACK_SCHEDULER: BackgroundScheduler | None = None
_SCHEDULER_LOCK = threading.Lock()
_COMMAND_TIMEOUT_SECONDS = 15
_MAX_BLOCK_MINUTES = 24 * 60
_CONTAINER_TARGET = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")


class SecurityPlaybooks:
    """Build dry-run responses for each mapped threat type."""

    @staticmethod
    def _validate_source_ip(src_ip: str, *, public_only: bool = False) -> str:
        try:
            parsed_ip = ipaddress.ip_address(src_ip)
        except ValueError as exc:
            raise ValueError(f"Invalid source IP address: {src_ip!r}") from exc
        if parsed_ip.version != 4:
            raise ValueError("The iptables playbooks currently require an IPv4 address")
        if public_only and not parsed_ip.is_global:
            raise ValueError("Refusing to block a non-public or reserved source IP")
        return str(parsed_ip)

    @staticmethod
    def temporary_ip_block(src_ip: str, duration_mins: int = 30) -> str:
        ip = SecurityPlaybooks._validate_source_ip(src_ip)
        if not 1 <= duration_mins <= _MAX_BLOCK_MINUTES:
            raise ValueError(f"duration_mins must be between 1 and {_MAX_BLOCK_MINUTES}")
        return (
            f"DRY RUN: would block {ip} for {duration_mins} minutes. "
            f"Rollback would remove the matching NetGuard rule."
        )

    @staticmethod
    def rate_limit_or_cloud_block(src_ip: str, sg_id: str | None = None) -> str:
        ip = SecurityPlaybooks._validate_source_ip(src_ip)
        if sg_id:
            if not re.fullmatch(r"sg-[0-9a-fA-F]+", sg_id):
                raise ValueError("sg_id must look like an AWS security group ID (sg-...)")
            return (
                f"DRY RUN: would revoke ingress from {ip}/32 in AWS security "
                f"group {sg_id}; no AWS request was sent."
            )
        return (
            "DRY RUN: would drop TCP packets above 25/minute per source; "
            "the matching NetGuard rule would be removed by rollback."
        )

    @staticmethod
    def isolate_host_or_container(container_id_or_ip: str) -> str:
        target = container_id_or_ip.strip()
        if not _CONTAINER_TARGET.fullmatch(target):
            raise ValueError("Target must be a valid Docker container name or ID")
        return (
            f"DRY RUN: would disconnect container {target} from bridge; "
            "it would be reconnected by rollback."
        )


def _execution_enabled() -> bool:
    return os.getenv(_EXECUTION_ENV, "").strip().casefold() in {"1", "true", "yes"}


def _validate_duration(duration_minutes: int) -> int:
    if not 1 <= duration_minutes <= _MAX_BLOCK_MINUTES:
        raise ValueError(f"duration_minutes must be between 1 and {_MAX_BLOCK_MINUTES}")
    return duration_minutes


def _container_target(value: object) -> str:
    if not isinstance(value, str) or not _CONTAINER_TARGET.fullmatch(value.strip()):
        raise ValueError("A valid container_id or container_name is required")
    return value.strip()


def _privileged_command(args: Sequence[str]) -> list[str]:
    """Return a non-interactive privileged command, refusing unsupported hosts."""
    if platform.system() != "Linux":
        raise RuntimeError("Executable firewall and Docker playbooks require Linux")
    if os.geteuid() == 0:
        return list(args)
    sudo = shutil.which("sudo")
    if not sudo:
        raise RuntimeError("sudo is required to run this playbook as a non-root user")
    return [sudo, "-n", *args]


def _run_command(args: Sequence[str]) -> None:
    command = _privileged_command(args)
    try:
        subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            shell=False,
            stdin=subprocess.DEVNULL,
            timeout=_COMMAND_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("System command timed out") from exc
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or "").strip()
        raise RuntimeError(detail or f"System command exited with {exc.returncode}") from exc


def _rollback_callback(args: list[str], playbook_id: str) -> None:
    try:
        _run_command(args)
    except Exception as exc:  # scheduler must record rollback failure without dying
        print(f"[ROLLBACK ERROR] {playbook_id}: {exc}")
    else:
        print(f"[ROLLBACK SUCCESS] {playbook_id}: mitigation reverted")


def _schedule_rollback(
    rollback_args: list[str], playbook_id: str, duration_minutes: int
) -> datetime:
    global _ROLLBACK_SCHEDULER
    with _SCHEDULER_LOCK:
        if _ROLLBACK_SCHEDULER is None:
            _ROLLBACK_SCHEDULER = BackgroundScheduler(timezone="UTC", daemon=True)
            _ROLLBACK_SCHEDULER.start()
        run_at = datetime.now(timezone.utc) + timedelta(minutes=duration_minutes)
        _ROLLBACK_SCHEDULER.add_job(
            _rollback_callback,
            trigger="date",
            run_date=run_at,
            args=[rollback_args, playbook_id],
            id=f"{playbook_id}-{uuid.uuid4().hex}",
            replace_existing=False,
        )
    return run_at


def _apply_with_rollback(
    apply_args: list[str],
    rollback_args: list[str],
    playbook_id: str,
    duration_minutes: int,
) -> str:
    duration_minutes = _validate_duration(duration_minutes)
    if not _execution_enabled():
        return (
            "DRY RUN: execution is disabled. Set NETGUARD_ENABLE_PLAYBOOK_EXECUTION=1 "
            "on a supported Linux host to enable approved actions."
        )

    _run_command(apply_args)
    try:
        rollback_at = _schedule_rollback(
            rollback_args, playbook_id, duration_minutes
        )
    except Exception:
        # Avoid leaving a temporary firewall rule in place if its rollback could
        # not be registered. The compensating command is still constrained.
        _run_command(rollback_args)
        raise
    return (
        f"SUCCESS: {playbook_id} applied. Rollback scheduled for "
        f"{rollback_at.isoformat()}."
    )


def execute_approved_playbook(
    playbook_id: str,
    anomaly_data: Mapping[str, object],
    *,
    approved: bool,
    duration_minutes: int = 30,
) -> str:
    """Run a mapped action only after graph approval; default mode is preview."""
    if approved is not True:
        return "CANCELLED: action was not approved by the human operator."

    playbook_to_threat = {
        "PB-001_TEMPORARY_IP_BLOCK": ThreatType.PORT_SCAN,
        "PB-002_RATE_LIMIT": ThreatType.HIGH_VOLUME_FLOOD,
        "PB-003_CONTAINER_ISOLATION": ThreatType.SUSPICIOUS_OUTBOUND,
        "PB-000_LOG_ONLY": ThreatType.UNKNOWN_ANOMALY,
    }
    threat = playbook_to_threat.get(playbook_id)
    if threat is None:
        return f"REFUSED: unsupported playbook identifier {playbook_id!r}."
    mapped = select_playbook(threat)

    if threat in {ThreatType.BENIGN_OUTLIER, ThreatType.UNKNOWN_ANOMALY}:
        return "LOG ONLY: assessment does not authorize a network change."

    if threat in {ThreatType.PORT_SCAN, ThreatType.HIGH_VOLUME_FLOOD}:
        raw_ip = anomaly_data.get("src_ip")
        if not isinstance(raw_ip, str):
            return "PLAYBOOK NOT RUN: a source IP is required."
        try:
            ip = SecurityPlaybooks._validate_source_ip(raw_ip, public_only=True)
            _validate_duration(duration_minutes)
        except ValueError as exc:
            return f"EXECUTION REFUSED: {exc}"

        marker = f"netguard-{mapped.playbook_id.lower()}-{uuid.uuid4().hex}"
        if threat is ThreatType.PORT_SCAN:
            apply_args = ["iptables", "-I", "INPUT", "-s", ip, "-m", "comment", "--comment", marker, "-j", "DROP"]
            rollback_args = ["iptables", "-D", "INPUT", "-s", ip, "-m", "comment", "--comment", marker, "-j", "DROP"]
        else:
            # Drop only traffic exceeding the per-source allowance; packets
            # within the allowance continue through the rest of INPUT policy.
            hash_name = f"ng{uuid.uuid4().hex[:24]}"
            apply_args = [
                "iptables", "-I", "INPUT", "-p", "tcp", "-s", ip,
                "-m", "hashlimit", "--hashlimit-above", "25/minute",
                "--hashlimit-burst", "50", "--hashlimit-mode", "srcip",
                "--hashlimit-name", hash_name, "-m", "comment", "--comment",
                marker, "-j", "DROP",
            ]
            rollback_args = apply_args.copy()
            rollback_args[1] = "-D"
        return _apply_with_rollback(
            apply_args, rollback_args, mapped.playbook_id, duration_minutes
        )

    # Docker's disconnect API requires a container name or ID, not the flow IP.
    raw_target = anomaly_data.get("container_id") or anomaly_data.get("container_name")
    try:
        target = _container_target(raw_target)
        _validate_duration(duration_minutes)
    except ValueError as exc:
        return f"PLAYBOOK NOT RUN: {exc}"
    return _apply_with_rollback(
        ["docker", "network", "disconnect", "bridge", target],
        ["docker", "network", "connect", "bridge", target],
        mapped.playbook_id,
        duration_minutes,
    )


def dispatch_playbook(
    threat_type: ThreatType | str,
    anomaly_data: Mapping[str, object],
) -> str:
    """Select and preview the playbook for a threat and its telemetry context."""
    playbook = select_playbook(threat_type)
    if playbook.threat_type is ThreatType.BENIGN_OUTLIER:
        return "LOG ONLY: LLM assessed the outlier as benign; no mitigation proposed."
    if playbook.threat_type is ThreatType.UNKNOWN_ANOMALY:
        return "LOG ONLY: unclassified anomaly flagged for manual review."
    if playbook.threat_type is ThreatType.PORT_SCAN:
        src_ip = anomaly_data.get("src_ip")
        if not isinstance(src_ip, str):
            return "PLAYBOOK NOT RUN: port-scan response requires a src_ip value."
        return SecurityPlaybooks.temporary_ip_block(src_ip)
    if playbook.threat_type is ThreatType.HIGH_VOLUME_FLOOD:
        src_ip = anomaly_data.get("src_ip")
        if not isinstance(src_ip, str):
            return "PLAYBOOK NOT RUN: flood response requires a src_ip value."
        sg_id = anomaly_data.get("sg_id")
        return SecurityPlaybooks.rate_limit_or_cloud_block(
            src_ip,
            sg_id if isinstance(sg_id, str) else None,
        )
    target = anomaly_data.get("container_id") or anomaly_data.get("container_name")
    if not isinstance(target, str):
        return (
            "PLAYBOOK NOT RUN: outbound isolation requires a container_id or "
            "container_name; a flow IP is not a Docker target."
        )
    return SecurityPlaybooks.isolate_host_or_container(target)
