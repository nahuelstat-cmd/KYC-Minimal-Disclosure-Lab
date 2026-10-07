"""Adversarial synthetic regressions, not live vendor conformance tests."""
import base64
from dataclasses import replace
import json
import unittest

from decision_gate import Decision, DecisionGate, Policy, Snapshot, decision_log
from lab_fixtures import SimulatedProvider, cases
from provider_profiles import ContractError, State, normalize, reuse_options
from privacy_audit import scan
import demo_proveedores


class ProviderControls(unittest.TestCase):
    def setUp(self):
        self.cases = cases()
        self.binding, self.approved, self.changed = self.cases['ripio']
        self.now = 1000.0
        self.clock = lambda: self.now
        self.provider = SimulatedProvider(self.binding, self.approved, self.clock)
        self.policy = Policy('a', self.binding, 1100.0)
        self.gate = DecisionGate(self.policy, self.provider.read, self.clock)

    def authorize(self):
        return self.gate.authorize('a', self.policy.digest)

    def test_completed_green_required(self):
        binding, good, _ = self.cases['sumsub']
        self.assertEqual(normalize(binding, good), State.APPROVED)
        for status in ('awaitingService', 'pending', 'awaitingUser', 'unrecognized'):
            with self.subTest(status=status):
                self.assertNotEqual(normalize(binding, dict(good, reviewStatus=status)), State.APPROVED)

    def test_sumsub_retry_final_unknown_and_level(self):
        binding, _, bad = self.cases['sumsub']
        self.assertEqual(normalize(binding, bad), State.REJECTED)
        for reject, expected in [('RETRY', State.RETRY), ('unexpected', State.UNKNOWN)]:
            bad['reviewResult']['reviewRejectType'] = reject
            self.assertEqual(normalize(binding, bad), expected)
        with self.assertRaises(ContractError):
            normalize(binding, dict(bad, levelName='weaker-level'))

    def test_truora_override_and_step_success(self):
        binding, good, bad = self.cases['truora']
        self.assertEqual(normalize(binding, bad), State.REJECTED)
        for status in (None, 'unrecognized', []):
            self.assertEqual(normalize(binding, dict(good, override_status=status)), State.UNKNOWN)
        self.assertEqual(normalize(binding, dict(good, status='pending',
                         last_finished_step={'status': 'success'})), State.PENDING)
        for key, value in [('process_id', 'other'), ('account_id', 'other'),
                           ('flow_id', 'other'), ('flow_version', 2)]:
            with self.subTest(key=key), self.assertRaises(ContractError):
                normalize(binding, dict(good, **{key: value}))

    def test_veriff_envelope_is_not_approval_or_aml(self):
        binding, good, _ = self.cases['veriff']
        self.assertEqual(normalize(binding, {'status': 'success'}), State.UNKNOWN)
        good['verification']['code'] = 9102
        good['verification']['pepSanctionMatch'] = False
        self.assertEqual(normalize(binding, good), State.UNKNOWN)
        good['verification']['code'] = 9001
        good['verification']['endUserId'] = 'another-person'
        with self.assertRaises(ContractError):
            normalize(binding, good)

    def test_malformed_objects_do_not_approve(self):
        for name, (binding, _, _) in self.cases.items():
            for bad in (None, [], 'success', {'status': []}, {'reviewStatus': []}):
                with self.subTest(provider=name, bad=bad):
                    try:
                        self.assertNotEqual(normalize(binding, bad), State.APPROVED)
                    except ContractError:
                        pass

    def test_share_token_does_not_approve(self):
        for name, (binding, _, _) in self.cases.items():
            with self.subTest(provider=name):
                try:
                    self.assertNotEqual(normalize(binding, {'shareToken': 'opaque-lab'}), State.APPROVED)
                except ContractError:
                    pass

    def test_conflicting_reuse_options_rejected(self):
        with self.assertRaises(ContractError):
            reuse_options(preservedVerificationStatus=True, requireFreshSelfie=True)
        self.assertEqual(reuse_options(), {'preservedVerificationStatus': False, 'requireFreshSelfie': True})
        with self.assertRaises(ContractError):
            reuse_options(requireFreshSelfie='true')

    def test_cached_approval_not_reused_after_change_or_outage(self):
        historical = self.authorize()
        self.assertTrue(historical.allowed)
        self.provider.payload = self.changed
        for _ in range(2):
            self.provider.notify(self.approved, authenticated=True)
        self.assertFalse(self.authorize().allowed)
        self.provider.unavailable = True
        self.assertEqual(self.authorize().reason, 'provider_unavailable')
        self.assertTrue(historical.allowed)  # A receipt is history, not a new permission.
        self.assertEqual(self.provider.read_calls, 3)

    def test_forged_notification_never_grants_or_logs_body(self):
        self.provider.payload = self.changed
        marker = demo_proveedores.MARKERS['documento']
        log = self.provider.notify({'status': 'COMPLETED', 'document': marker}, authenticated=False)
        self.assertEqual(log['result'], 'rejected')
        self.assertNotIn(marker, json.dumps(log))
        self.assertFalse(self.authorize().allowed)

    def test_policy_and_audience_substitution_prevent_read(self):
        self.assertFalse(self.gate.authorize('b', self.policy.digest).allowed)
        changed = replace(self.policy, version='weaker-v0')
        self.assertFalse(self.gate.authorize('a', changed.digest).allowed)
        self.assertEqual(self.provider.read_calls, 0)

    def test_expiration_before_and_during_read(self):
        self.now = 1100
        self.assertEqual(self.authorize().reason, 'authorization_expired')
        self.assertEqual(self.provider.read_calls, 0)
        self.now = 1099
        def slow(binding):
            self.now = 1101
            return Snapshot(binding, self.now, self.approved)
        self.gate.fetch = slow
        self.assertEqual(self.authorize().reason, 'authorization_expired')

    def test_old_future_nan_or_wrong_resource_snapshot(self):
        for observed in (999.0, 1001.0, float('nan')):
            self.gate.fetch = lambda b: Snapshot(b, observed, self.approved)
            self.assertEqual(self.authorize().reason, 'stale_or_invalid_read')
        self.gate.fetch = lambda b: Snapshot(replace(b, resource_id='other'), 1000, self.approved)
        self.assertEqual(self.authorize().reason, 'binding_mismatch')

    def test_slow_read_and_clock_rollback(self):
        def slow(binding):
            self.now += 6
            return Snapshot(binding, self.now, self.approved)
        self.gate.fetch = slow
        self.assertEqual(self.authorize().reason, 'stale_or_invalid_read')
        def rollback(binding):
            self.now -= 1
            return Snapshot(binding, self.now, self.approved)
        self.gate.fetch = rollback
        self.assertEqual(self.authorize().reason, 'stale_or_invalid_read')

    def test_body_customer_mismatch(self):
        self.provider.payload['customerId'] = 'other'
        self.assertEqual(self.authorize().reason, 'invalid_contract')

    def test_exception_details_and_arbitrary_values_not_logged(self):
        marker = demo_proveedores.MARKERS['nombre']
        def fail(binding):
            raise TimeoutError(marker)
        self.gate.fetch = fail
        self.assertNotIn(marker, json.dumps(decision_log(self.authorize())))
        with self.assertRaises(ValueError):
            decision_log(Decision(False, marker))

    def test_demo_runs_both_services_for_all_profiles(self):
        result = demo_proveedores.run()
        self.assertEqual(result['estado'], 'PASS')
        self.assertEqual(sum(p['simulated_reads'] for p in result['perfiles']), 24)
        for profile in result['perfiles']:
            self.assertEqual(set(profile['current_after_change']), {'a', 'b'})


class PrivacyControls(unittest.TestCase):
    def setUp(self):
        self.markers = demo_proveedores.MARKERS
        self.raw = json.dumps(self.markers, sort_keys=True).encode()

    def test_literal_base64_base64url_jwt_and_nested(self):
        b64 = base64.b64encode(self.raw)
        url = base64.urlsafe_b64encode(self.raw).rstrip(b'=')
        vectors = [self.raw, b64, url, b'eyJhbGciOiJub25lIn0.' + url + b'.signature',
                   base64.b64encode(json.dumps({'body': b64.decode()}).encode())]
        for vector in vectors:
            with self.subTest(vector=vector[:10]):
                result = scan(vector, self.markers)
                self.assertEqual(result['marcadores_PII'], sorted(self.markers))
                self.assertTrue(result['escaneo_acotado_completo'])
                # Diagnostic must not itself make a fresh copy of the canary values.
                self.assertTrue(all(v not in json.dumps(result) for v in self.markers.values()))

    def test_limits_never_report_complete_scan(self):
        for opts in ({'max_bytes': 5}, {'max_depth': 0}, {'max_nodes': 1}):
            result = scan(base64.b64encode(self.raw), self.markers, **opts)
            self.assertFalse(result['escaneo_acotado_completo'])
            self.assertTrue(result['limites_alcanzados'])

    def test_invalid_base64_and_clean_log(self):
        for value in (b'@@@bad==', b'{"event":"complete","allowed":true}'):
            result = scan(value, self.markers)
            self.assertFalse(result['marcadores_PII'])
            self.assertTrue(result['escaneo_acotado_completo'])


if __name__ == '__main__':
    unittest.main()
