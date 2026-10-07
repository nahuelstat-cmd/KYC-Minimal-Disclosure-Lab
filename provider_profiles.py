"""Offline contract projections, not provider SDKs or authenticated API clients.

Inputs must come from a trusted server-side transport. In this repository that
transport is a fixture. Status means provider process status, not age or AML.
See docs/proveedores.md for the supported subsets and trust boundary.
"""
from dataclasses import dataclass
from enum import Enum


class State(str, Enum):
    APPROVED = 'approved'
    REJECTED = 'rejected'
    RETRY = 'retry'
    PENDING = 'pending'
    UNKNOWN = 'unknown'


class ContractError(ValueError):
    """Static errors only: never embed the rejected payload in diagnostics."""


@dataclass(frozen=True)
class Binding:
    provider: str
    resource_id: str
    subject_id: str
    profile: str
    profile_version: int = 1


def obj(value):
    if not isinstance(value, dict):
        raise ContractError('invalid_object')
    return value


def match(actual, expected):
    if type(actual) is not type(expected) or actual != expected:
        raise ContractError('binding_mismatch')


def normalize(binding, payload):
    """Return one enum; omit identity data, comments, tokens and raw response."""
    p = obj(payload)
    if binding.provider == 'ripio':
        # The documented read result is customer-scoped, not submission-scoped.
        match(binding.resource_id, binding.subject_id)
        match(p.get('customerId'), binding.subject_id)
        status = p.get('status')
        if not isinstance(status, str):
            return State.UNKNOWN
        return {'COMPLETED': State.APPROVED, 'FAILED': State.REJECTED,
                'IN_REVIEW': State.PENDING}.get(status, State.UNKNOWN)
    if binding.provider == 'sumsub':
        # /status omits applicantId: the trusted transport must bind the path.
        match(p.get('levelName'), binding.profile)
        status = p.get('reviewStatus')
        if status != 'completed':
            return State.PENDING if status in (
                'init', 'pending', 'prechecked', 'queued', 'onHold',
                'awaitingService', 'awaitingUser') else State.UNKNOWN
        result = obj(p.get('reviewResult'))
        if result.get('reviewAnswer') == 'GREEN':
            return State.APPROVED
        if result.get('reviewAnswer') == 'RED':
            if result.get('reviewRejectType') == 'RETRY':
                return State.RETRY
            if result.get('reviewRejectType') == 'FINAL':
                return State.REJECTED
        return State.UNKNOWN
    if binding.provider == 'truora':
        match(p.get('process_id'), binding.resource_id)
        match(p.get('account_id'), binding.subject_id)
        match(p.get('flow_id'), binding.profile)
        match(p.get('flow_version'), binding.profile_version)
        # Presence matters: null/unknown overrides cannot fall back to success.
        status = p['override_status'] if 'override_status' in p else p.get('status')
        if not isinstance(status, str):
            return State.UNKNOWN
        return {'success': State.APPROVED, 'failure': State.REJECTED,
                'pending': State.PENDING}.get(status, State.UNKNOWN)
    if binding.provider == 'veriff':
        if p.get('status') != 'success' or p.get('verification') is None:
            return State.UNKNOWN
        v = obj(p['verification'])
        match(v.get('id'), binding.resource_id)
        # This lab requires endUserId to have been assigned at session creation.
        match(v.get('endUserId'), binding.subject_id)
        if not isinstance(v.get('attemptId'), str) or not v['attemptId']:
            return State.UNKNOWN
        if v.get('status') == 'approved':
            return State.APPROVED if type(v.get('code')) is int and v['code'] == 9001 else State.UNKNOWN
        status = v.get('status')
        if not isinstance(status, str):
            return State.UNKNOWN
        return {'declined': State.REJECTED, 'expired': State.REJECTED,
                'abandoned': State.REJECTED, 'resubmission_requested': State.RETRY,
                'review': State.PENDING}.get(status, State.UNKNOWN)
    raise ContractError('unsupported_provider')


def reuse_options(*, preservedVerificationStatus=False, requireFreshSelfie=True):
    """Lab policy: do not silently claim a fresh selfie when it will be ignored."""
    if type(preservedVerificationStatus) is not bool or type(requireFreshSelfie) is not bool:
        raise ContractError('boolean_required')
    if preservedVerificationStatus and requireFreshSelfie:
        raise ContractError('fresh_selfie_would_be_ignored')
    return {'preservedVerificationStatus': preservedVerificationStatus,
            'requireFreshSelfie': requireFreshSelfie}
