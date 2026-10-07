"""Single-process simulation of a fresh read before each authorization.

No HTTP, no provider credentials, no money movements. Fetch and timestamps
are trusted in-process fixtures, not cryptographic proofs of provider state.
"""
from dataclasses import asdict, dataclass
import hashlib
import json
import math
import time

from provider_profiles import Binding, ContractError, State, normalize


@dataclass(frozen=True)
class Policy:
    audience: str
    binding: Binding
    valid_until: float
    max_read_seconds: float = 5.0
    version: str = 'provider-status-lab/v1'

    def __post_init__(self):
        if (not math.isfinite(self.valid_until) or
                not math.isfinite(self.max_read_seconds) or self.max_read_seconds <= 0):
            raise ValueError('invalid_policy_time')

    @property
    def digest(self):
        data = json.dumps(asdict(self), sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(data.encode()).hexdigest()


@dataclass(frozen=True)
class Snapshot:
    # Transport metadata; these fields are NOT part of any provider's JSON.
    binding: Binding
    observed_at: float
    payload: dict


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


class DecisionGate:
    def __init__(self, policy, fetch, clock=time.time):
        self.policy, self.fetch, self.clock = policy, fetch, clock

    def authorize(self, audience, policy_digest):
        p = self.policy
        if audience != p.audience or policy_digest != p.digest:
            return Decision(False, 'context_mismatch')
        started = self.clock()
        if not math.isfinite(started) or started >= p.valid_until:
            return Decision(False, 'authorization_expired')
        # No positive cache, webhook payload or historical receipt is consulted.
        try:
            snapshot = self.fetch(p.binding)
        except (OSError, TimeoutError):
            return Decision(False, 'provider_unavailable')
        now = self.clock()
        if not isinstance(snapshot, Snapshot) or snapshot.binding != p.binding:
            return Decision(False, 'binding_mismatch')
        if (type(snapshot.observed_at) not in (int, float) or
                not all(math.isfinite(v) for v in (now, snapshot.observed_at)) or
                not started <= snapshot.observed_at <= now or
                now - started > p.max_read_seconds):
            return Decision(False, 'stale_or_invalid_read')
        if now >= p.valid_until:
            return Decision(False, 'authorization_expired')
        try:
            state = normalize(p.binding, snapshot.payload)
        except ContractError:
            return Decision(False, 'invalid_contract')
        return Decision(state is State.APPROVED, state.value)


def decision_log(decision):
    """An allowlist of values as well as keys: no exception/body interpolation."""
    reasons = {s.value for s in State} | {
        'context_mismatch', 'authorization_expired', 'provider_unavailable',
        'binding_mismatch', 'stale_or_invalid_read', 'invalid_contract'}
    if type(decision.allowed) is not bool or decision.reason not in reasons:
        raise ValueError('invalid_log_value')
    return {'event': 'authorization_checked', 'allowed': decision.allowed,
            'reason': decision.reason, 'scope': 'SIMULADO'}
