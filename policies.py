"""Threat-to-playbook policy mapping for the mitigation layer.

This module describes proposed responses only. It does not run shell commands,
change firewall rules, call AWS, or disconnect containers.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Mapping


class ThreatType(str, Enum):
    """Threat labels expected from the forthcoming triage layer."""

    PORT_SCAN = "PORT_SCAN"
    HIGH_VOLUME_FLOOD = "HIGH_VOLUME_FLOOD"
    SUSPICIOUS_OUTBOUND = "SUSPICIOUS_OUTBOUND"
    BENIGN_OUTLIER = "BENIGN_OUTLIER"
    UNKNOWN_ANOMALY = "UNKNOWN_ANOMALY"


@dataclass(frozen=True)
class PlaybookDefinition:
    """A policy entry and its proposed action; command text is illustrative."""

    playbook_id: str
    threat_type: ThreatType
    trigger_condition: str
    action: str
    command_template: str | None
    required_parameters: tuple[str, ...] = ()
    execution_mode: str = "human_approved_and_explicitly_enabled"


POLICY_MAPPING: Mapping[ThreatType, PlaybookDefinition] = MappingProxyType(
    {
        ThreatType.PORT_SCAN: PlaybookDefinition(
            playbook_id="PB-001",
            threat_type=ThreatType.PORT_SCAN,
            trigger_condition=(
                "High unique destination-port count combined with small packet size."
            ),
            action="Propose a temporary source-IP block.",
            command_template="iptables -A INPUT -s {src_ip} -j DROP",
            required_parameters=("src_ip",),
        ),
        ThreatType.HIGH_VOLUME_FLOOD: PlaybookDefinition(
            playbook_id="PB-002",
            threat_type=ThreatType.HIGH_VOLUME_FLOOD,
            trigger_condition="Extreme packet rate or packet count.",
            action="Propose rate limiting or an AWS security-group ingress block.",
            command_template=(
                "iptables -A INPUT -p tcp -s {src_ip} "
                "-m limit --limit 25/minute -j ACCEPT"
            ),
            required_parameters=("src_ip",),
        ),
        ThreatType.SUSPICIOUS_OUTBOUND: PlaybookDefinition(
            playbook_id="PB-003",
            threat_type=ThreatType.SUSPICIOUS_OUTBOUND,
            trigger_condition=(
                "Abnormal outbound flow duration to an external destination."
            ),
            action="Propose isolating the affected container from its bridge network.",
            command_template="docker network disconnect bridge {container_id}",
            required_parameters=("container_id",),
        ),
        ThreatType.UNKNOWN_ANOMALY: PlaybookDefinition(
            playbook_id="PB-000",
            threat_type=ThreatType.UNKNOWN_ANOMALY,
            trigger_condition="An anomaly was detected but no threat type was assigned.",
            action="Log the anomaly and send it for manual review.",
            command_template=None,
        ),
        ThreatType.BENIGN_OUTLIER: PlaybookDefinition(
            playbook_id="PB-000",
            threat_type=ThreatType.BENIGN_OUTLIER,
            trigger_condition=(
                "An outlier has telemetry supporting a benign explanation and no clear threat marker."
            ),
            action="Record the benign outlier without a mitigation action.",
            command_template=None,
        ),
    }
)


def select_playbook(threat_type: ThreatType | str) -> PlaybookDefinition:
    """Return the mapped playbook, falling back to manual review if unknown."""
    try:
        normalized_type = (
            threat_type
            if isinstance(threat_type, ThreatType)
            else ThreatType(str(threat_type).strip().upper())
        )
    except ValueError:
        normalized_type = ThreatType.UNKNOWN_ANOMALY
    return POLICY_MAPPING[normalized_type]

