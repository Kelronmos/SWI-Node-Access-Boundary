"""
SWI Node-Access Boundary — Contracts (Stage 1 demonstrator)

Implements the data model from "SWI Distributed Node Isolation & Rebuild
Manual" Sections 6-12 and 31: node identity, module identity, resource
contracts, and the access-request/authorization shapes the boundary
enforces.

STATUS: Stage 1 demonstrator. This is a NEW, standalone package — it does
not modify swi_core (V1) or swi_v2 (V2) internals, per Section 13/14 of the
source manual ("do not introduce hidden dependencies... implement as a
clearly defined boundary around execution rather than silently importing
internals"). It imports V1's module classes (SecurityProbe, RedactionEngine,
DriftAnalyzer) only as example callers, unmodified.

This is a single-process SIMULATION of node separation (three logical
"nodes" as Python objects, not three physical machines) — a real, testable
proof of the access-control logic, not a claim of physical distribution.
Extending this to genuinely separate machines/processes is future work
(Section 34 calls this the correct order: prove the boundary logic first).
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


class Operation(str, Enum):
    READ = "READ"
    WRITE = "WRITE"


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    HALT = "HALT"


@dataclass(frozen=True)
class NodeIdentity:
    """An identity reference for a node. NOT an access credential
    (Section 7): possessing a node_id proves nothing on its own.
    """

    node_id: str


@dataclass(frozen=True)
class ModuleIdentity:
    """An identity reference for a module (Section 8)."""

    module_id: str


@dataclass(frozen=True)
class ResourceContract:
    """A single, explicit grant: this module may perform this operation
    on this resource, on this node, until this time. Narrower than
    node-level authorization by construction (Section 9) — there is no
    field here that means "everything on this node".
    """

    module_id: str
    node_id: str
    resource: str
    operation: Operation
    workflow_id: str
    expires_at: Optional[float] = None  # unix time; None = no expiry
    contract_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])

    def integrity_reference(self) -> str:
        """Hash over the fields that define what was actually granted.
        Excludes contract_id (an identifier, not a granted property).
        """
        material = {
            "module_id": self.module_id,
            "node_id": self.node_id,
            "resource": self.resource,
            "operation": self.operation.value,
            "workflow_id": self.workflow_id,
            "expires_at": self.expires_at,
        }
        encoded = json.dumps(material, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AccessRequest:
    """What a module is actually asking for, right now."""

    module: ModuleIdentity
    node: NodeIdentity
    resource: str
    operation: Operation
    workflow_id: str
    requested_at: float = field(default_factory=time.time)


@dataclass(frozen=True)
class AccessDecisionRecord:
    """The evidence record for one access decision (Sections 10, 25)."""

    decision: Decision
    reason: str
    request: AccessRequest
    contract_id: Optional[str]
    decided_at: float = field(default_factory=time.time)

    def to_evidence_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision.value,
            "reason": self.reason,
            "module_id": self.request.module.module_id,
            "node_id": self.request.node.node_id,
            "resource": self.request.resource,
            "operation": self.request.operation.value,
            "workflow_id": self.request.workflow_id,
            "contract_id": self.contract_id,
            "requested_at": self.request.requested_at,
            "decided_at": self.decided_at,
        }
