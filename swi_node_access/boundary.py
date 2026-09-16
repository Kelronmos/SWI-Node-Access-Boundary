"""
SWI Node-Access Boundary — Enforcement (Stage 1 demonstrator)

Implements Sections 10 (ALLOW/DENY/HALT), 11 (no direct node pulling —
requests must go through this boundary), 27 (fail-closed rule), 29 (node
discovery must not create access rights), and 30 (no implicit
module-to-module trust) from the source manual.

Fail-closed means: any condition this boundary cannot cleanly resolve
results in HALT, never a default ALLOW. There is no code path here that
falls through to "allow" without an explicit, matching, unexpired,
untampered ResourceContract.
"""
from __future__ import annotations

from typing import Dict, List

from .contracts import (
    AccessDecisionRecord,
    AccessRequest,
    Decision,
    ResourceContract,
)


class AccessBoundary:
    """Enforces ALLOW/DENY/HALT for AccessRequests against a set of
    explicitly registered ResourceContracts.

    Registering a contract is the ONLY way a request can be ALLOWed.
    Nothing here infers a contract from a node being reachable, from a
    node_id being known, or from another module's prior success — those
    would be exactly the escalation paths Sections 29-30 prohibit.
    """

    def __init__(self) -> None:
        self._contracts: Dict[str, ResourceContract] = {}
        self._discovered_nodes: set[str] = set()
        self._evidence_log: List[AccessDecisionRecord] = []

    # -- Section 29: discovery is tracked separately and NEVER checked
    #    by decide(); it exists only so tests can prove discovery alone
    #    grants nothing. --
    def discover_node(self, node_id: str) -> None:
        self._discovered_nodes.add(node_id)

    def is_discovered(self, node_id: str) -> bool:
        return node_id in self._discovered_nodes

    def register_contract(self, contract: ResourceContract) -> str:
        self._contracts[contract.contract_id] = contract
        return contract.contract_id

    def revoke_contract(self, contract_id: str) -> None:
        self._contracts.pop(contract_id, None)

    def tamper_contract_for_testing(self, contract_id: str, **field_overrides) -> None:
        """Test-only: mutate a stored contract's fields WITHOUT updating
        any external integrity reference, simulating an attacker
        modifying a stored authorization record directly.
        """
        existing = self._contracts[contract_id]
        object.__setattr__(existing, "_tampered_fields", field_overrides)
        for k, v in field_overrides.items():
            object.__setattr__(existing, k, v)

    def _find_matching_contract(self, request: AccessRequest) -> ResourceContract | None:
        for contract in self._contracts.values():
            if (
                contract.module_id == request.module.module_id
                and contract.node_id == request.node.node_id
                and contract.resource == request.resource
                and contract.operation == request.operation
                and contract.workflow_id == request.workflow_id
            ):
                return contract
        return None

    def decide(self, request: AccessRequest) -> AccessDecisionRecord:
        try:
            contract = self._find_matching_contract(request)
        except Exception as exc:  # noqa: BLE001 - fail closed on ANY lookup error
            record = AccessDecisionRecord(
                decision=Decision.HALT,
                reason=f"authorization lookup raised {type(exc).__name__}: {exc}",
                request=request,
                contract_id=None,
            )
            self._evidence_log.append(record)
            return record

        if contract is None:
            record = AccessDecisionRecord(
                decision=Decision.DENY,
                reason="no matching authorization for this module/node/resource/operation/workflow",
                request=request,
                contract_id=None,
            )
            self._evidence_log.append(record)
            return record

        # Tamper check: did anything about this contract change since it
        # was integrity-referenced? A real deployment would compare
        # against an externally-stored reference (e.g. signed at issuance,
        # per CRTG); here, tamper_contract_for_testing() marks tampered
        # fields explicitly so this check has something concrete to catch.
        if getattr(contract, "_tampered_fields", None):
            record = AccessDecisionRecord(
                decision=Decision.HALT,
                reason=f"authorization record integrity check failed: fields {list(contract._tampered_fields)} were modified after issuance",
                request=request,
                contract_id=contract.contract_id,
            )
            self._evidence_log.append(record)
            return record

        if contract.expires_at is not None and request.requested_at > contract.expires_at:
            record = AccessDecisionRecord(
                decision=Decision.DENY,
                reason=f"authorization expired at {contract.expires_at}, request at {request.requested_at}",
                request=request,
                contract_id=contract.contract_id,
            )
            self._evidence_log.append(record)
            return record

        record = AccessDecisionRecord(
            decision=Decision.ALLOW,
            reason="matched an active, untampered, unexpired authorization",
            request=request,
            contract_id=contract.contract_id,
        )
        self._evidence_log.append(record)
        return record

    def evidence_log(self) -> List[AccessDecisionRecord]:
        return list(self._evidence_log)
