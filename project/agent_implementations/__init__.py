"""Specialized AI agents for Major-Project pentesting."""
from project.agent_implementations.asset_discovery_agent import new_asset_discovery_agent
from project.agent_implementations.threat_intel_agent import new_threat_intel_agent
from project.agent_implementations.attack_surface_agent import new_attack_surface_agent
from project.agent_implementations.vulnerability_reasoner_agent import new_vulnerability_reasoner_agent
from project.agent_implementations.exploit_gen_agent import new_exploit_gen_agent
from project.agent_implementations.payload_mutation_agent import new_payload_mutation_agent
from project.agent_implementations.verification_safety_agent import new_verification_safety_agent
from project.agent_implementations.reporting_agent import new_reporting_agent

__all__ = [
    "new_asset_discovery_agent",
    "new_threat_intel_agent",
    "new_attack_surface_agent",
    "new_vulnerability_reasoner_agent",
    "new_exploit_gen_agent",
    "new_payload_mutation_agent",
    "new_verification_safety_agent",
    "new_reporting_agent",
]