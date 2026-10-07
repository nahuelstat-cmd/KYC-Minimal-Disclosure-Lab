"""Offline comparison: cached approval vs fresh authorization; unsafe vs safe log."""
import base64
import json
from pathlib import Path

from decision_gate import DecisionGate, Policy, decision_log
from lab_fixtures import SimulatedProvider, cases
from privacy_audit import scan

MARKERS = {'nombre': 'NOMBRE_SINTETICO_LAB_438106',
           'documento': 'DOCUMENTO_SINTETICO_LAB_874209',
           'nacimiento': 'DOB_SINTETICO_LAB_1948_02_29'}


def run():
    records, controls = [], {}
    for name, (binding, approved, changed) in cases().items():
        # Fixed clock: deterministic functional simulation, not a latency benchmark.
        clock = lambda: 1000.0
        provider = SimulatedProvider(binding, approved, clock)
        gates = {a: DecisionGate(Policy(a, binding, 1100.0), provider.read, clock)
                 for a in ('a', 'b')}
        initial = {a: g.authorize(a, g.policy.digest) for a, g in gates.items()}
        # Modeled old design: a stored approval reused without reconciliation.
        old_cache = {a: d.allowed for a, d in initial.items()}
        provider.payload = changed
        # A late or repeated success event cannot overwrite the fresh read.
        notifications = [provider.notify(approved, authenticated=True) for _ in range(2)]
        current = {a: g.authorize(a, g.policy.digest) for a, g in gates.items()}
        provider.unavailable = True
        outage = {a: g.authorize(a, g.policy.digest) for a, g in gates.items()}
        controls[name + '_initial_approval'] = all(d.allowed for d in initial.values())
        controls[name + '_changed_status_blocks_both'] = all(not d.allowed for d in current.values())
        controls[name + '_outage_does_not_reuse_approval'] = all(not d.allowed for d in outage.values())
        controls[name + '_fresh_read_each_action'] = provider.read_calls == 6
        records.append({'profile': name, 'cached_baseline_after_change': old_cache,
                        'current_after_change': {a: decision_log(d) for a, d in current.items()},
                        'during_outage': {a: decision_log(d) for a, d in outage.items()},
                        'notifications': notifications, 'simulated_reads': provider.read_calls})

    # Positive control: raw-body logging retains data even when encoded.
    encoded = base64.b64encode(json.dumps(MARKERS, sort_keys=True).encode()).decode()
    unsafe = json.dumps({'rawBodyBase64': encoded}).encode()
    safe = json.dumps(records, sort_keys=True).encode()
    baseline, minimized = scan(unsafe, MARKERS), scan(safe, MARKERS)
    literal_count = sum(v.encode() in unsafe for v in MARKERS.values())
    controls['positive_control_hidden_base64'] = (
        literal_count == 0 and len(baseline['marcadores_PII']) == len(MARKERS))
    controls['allowlisted_logs_no_canaries'] = (
        minimized['escaneo_acotado_completo'] and not minimized['marcadores_PII'])
    return {'estado': 'PASS' if all(controls.values()) else 'FAIL',
            'alcance': 'SIMULADO; cuatro perfiles, un proceso; cero APIs KYC reales',
            'controles': controls, 'control_count': len(controls), 'perfiles': records,
            'logs_control_positivo': {'literal_markers': literal_count,
                                      'encoded_markers': baseline['marcadores_PII']},
            'logs_minimos': minimized,
            'no_demostrado': ['conformidad SDK/API', 'autenticacion del proveedor',
                             'freshness del backend remoto', 'identidad humana',
                             'AML', 'aceptacion legal', 'concurrencia distribuida',
                             'costos o latencia productiva', 'dos backends criptograficos']}


def main():
    result = run()
    Path(__file__).with_name('resultado_proveedores.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(result['estado'], result['control_count'], 'controles de perfiles; 4 proveedores SIMULADOS')
    if result['estado'] != 'PASS':
        raise RuntimeError('Fallaron controles: ' + ', '.join(
            k for k, v in result['controles'].items() if not v))
    print('Base64: 0 marcadores con busqueda literal, 3 al decodificar; 0 en logs minimos.')


if __name__ == '__main__':
    main()
