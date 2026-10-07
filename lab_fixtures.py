"""Synthetic subsets of documented results. Never import these in production."""
from copy import deepcopy
import time
from decision_gate import Snapshot
from provider_profiles import Binding


def cases():
    return {
        'ripio': (
            Binding('ripio', 'customer-lab', 'customer-lab', 'hosted-lab'),
            {'customerId': 'customer-lab', 'status': 'COMPLETED'},
            {'customerId': 'customer-lab', 'status': 'FAILED'}),
        'sumsub': (
            Binding('sumsub', 'applicant-lab', 'account-lab', 'kyc-lab'),
            {'levelName': 'kyc-lab', 'reviewStatus': 'completed',
             'reviewResult': {'reviewAnswer': 'GREEN'}},
            {'levelName': 'kyc-lab', 'reviewStatus': 'completed',
             'reviewResult': {'reviewAnswer': 'RED', 'reviewRejectType': 'FINAL'}}),
        'truora': (
            Binding('truora', 'process-lab', 'account-lab', 'flow-lab'),
            {'process_id': 'process-lab', 'account_id': 'account-lab',
             'flow_id': 'flow-lab', 'flow_version': 1, 'status': 'success'},
            {'process_id': 'process-lab', 'account_id': 'account-lab',
             'flow_id': 'flow-lab', 'flow_version': 1, 'status': 'success',
             'override_status': 'failure'}),
        'veriff': (
            Binding('veriff', 'session-lab', 'account-lab', 'identity-lab'),
            {'status': 'success', 'verification': {'id': 'session-lab',
             'endUserId': 'account-lab', 'attemptId': 'attempt-lab',
             'status': 'approved', 'code': 9001}},
            {'status': 'success', 'verification': {'id': 'session-lab',
             'endUserId': 'account-lab', 'attemptId': 'attempt-lab',
             'status': 'declined', 'code': 9102}}),
    }


class SimulatedProvider:
    def __init__(self, binding, payload, clock=time.time):
        self.binding, self.payload, self.clock = binding, deepcopy(payload), clock
        self.unavailable, self.read_calls = False, 0

    def read(self, requested_binding):
        self.read_calls += 1
        if self.unavailable:
            raise TimeoutError('synthetic_provider_timeout')
        if requested_binding != self.binding:
            raise ValueError('fixture_binding_mismatch')
        return Snapshot(self.binding, self.clock(), deepcopy(self.payload))

    def notify(self, payload, *, authenticated):
        # Authentication is an explicit fixture result, NOT signature validation.
        # Neither a positive nor a negative notification replaces current state.
        # A live service could enqueue reconciliation; this lab reads per action.
        return {'event': 'notification_received',
                'result': 'accepted' if authenticated is True else 'rejected',
                'scope': 'SIMULADO'}
