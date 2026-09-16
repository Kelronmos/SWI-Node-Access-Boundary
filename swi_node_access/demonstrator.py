"""
SWI Node-Access Boundary — Stage 1 Demonstrator (Section 34)

Wires three REAL, unmodified V1 modules to three simulated node identities:

    M02 (SecurityProbe)    -> NODE-A
    M05 (RedactionEngine)  -> NODE-B
    M06 (DriftAnalyzer)    -> NODE-C

Each module's real work only happens AFTER an AccessBoundary.decide()
returns ALLOW for that module/node/resource/operation/workflow tuple.
This proves the boundary sits in front of real execution, not beside it
(the same standard M11's kernel enforcement was already held to).

V1 itself is imported read-only and never modified, per Section 13.

NOTE: The V1 path below is a placeholder for the machine where V1 is
checked out. Adjust _V1_ROOT (or install V1 as a package) before running
the demonstrator tests that exercise real modules.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

# Import real, unmodified V1 modules for the demonstrator.
# Adjust this path to your local checkout of SWI-V1-Module-1-10.
_V1_ROOT = Path(__file__).resolve().parents[2] / "SWI-V1-Module-1-10"
if _V1_ROOT.exists() and str(_V1_ROOT) not in sys.path:
    sys.path.insert(0, str(_V1_ROOT))

try:
    from swi_core.module02_security_probe import SecurityProbe  # noqa: E402
    from swi_core.module05_redaction_engine import RedactionEngine  # noqa: E402
    from swi_core.module06_drift_analyzer import DriftAnalyzer  # noqa: E402
    _V1_AVAILABLE = True
except ImportError:
    SecurityProbe = None  # type: ignore
    RedactionEngine = None  # type: ignore
    DriftAnalyzer = None  # type: ignore
    _V1_AVAILABLE = False

from .boundary import AccessBoundary
from .contracts import AccessRequest, ModuleIdentity, NodeIdentity, Operation


class UnauthorizedAccessError(RuntimeError):
    """Raised when a demonstrator module's request is DENY'd or HALT'd."""


class NodeBoundModule:
    """Wraps a real V1 module instance so its work only runs after an
    explicit ALLOW from the AccessBoundary — the module itself is never
    modified; the check happens at the call site, matching Section 11's
    "boundary is the enforcement point" model.
    """

    def __init__(
        self,
        boundary: AccessBoundary,
        module_id: str,
        node_id: str,
        resource: str,
        workflow_id: str,
        real_module: Any,
    ):
        self.boundary = boundary
        self.module = ModuleIdentity(module_id)
        self.node = NodeIdentity(node_id)
        self.resource = resource
        self.workflow_id = workflow_id
        self.real_module = real_module

    def _check(self, operation: Operation) -> None:
        request = AccessRequest(
            module=self.module,
            node=self.node,
            resource=self.resource,
            operation=operation,
            workflow_id=self.workflow_id,
        )
        decision = self.boundary.decide(request)
        if decision.decision.value != "ALLOW":
            raise UnauthorizedAccessError(
                f"{decision.decision.value}: {decision.reason}"
            )

    def run_m02_scan(self, text: str):
        self._check(Operation.READ)
        return self.real_module.scan(text)

    def run_m05_redact(self, text: str):
        self._check(Operation.READ)
        return self.real_module.redact(text)

    def run_m06_check(self, text: str):
        self._check(Operation.READ)
        return self.real_module.check(text)


def build_demonstrator(boundary: AccessBoundary, workflow_id: str = "demo-workflow-001"):
    """Constructs the three node-bound modules used by the demonstrator
    and adversarial tests. Registering contracts is a SEPARATE, explicit
    step (see test file) — building the demonstrator does not itself
    grant any access.

    Requires a local checkout of SWI-V1-Module-1-10 (or installed package)
    so the real M02/M05/M06 classes can be imported.
    """
    if not _V1_AVAILABLE:
        raise ImportError(
            "V1 modules not importable. Clone SWI-V1-Module-1-10 next to this "
            "repo or install it, then adjust _V1_ROOT in demonstrator.py."
        )
    m02 = NodeBoundModule(
        boundary, "M02", "NODE-A", "RESOURCE-TEXT-INPUT", workflow_id,
        SecurityProbe(block_threshold=0.5),
    )
    m05 = NodeBoundModule(
        boundary, "M05", "NODE-B", "RESOURCE-TEXT-INPUT", workflow_id,
        RedactionEngine(),
    )
    m06 = NodeBoundModule(
        boundary, "M06", "NODE-C", "RESOURCE-TEXT-INPUT", workflow_id,
        DriftAnalyzer(drift_threshold=0.35),
    )
    return m02, m05, m06
