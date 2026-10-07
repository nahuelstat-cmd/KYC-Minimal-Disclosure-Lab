"""Bounded canary scanner: literal bytes plus nested Base64/Base64URL/JWT.

Not a general PII detector. It neither verifies JWT signatures nor decrypts
data. Compression, OCR, split values, other encodings and external sinks are
outside coverage. Reports names of canaries, never their recovered values.
"""
import base64
import binascii
from collections import deque
import re

TOKEN = re.compile(rb'(?<![A-Za-z0-9_+/=-])[A-Za-z0-9_+/-]{16,}={0,2}(?![A-Za-z0-9_+/=-])')


def scan(data, markers, *, max_bytes=1048576, max_depth=3, max_nodes=1024):
    if max_bytes < 1 or max_depth < 0 or max_nodes < 1:
        raise ValueError('invalid_scan_limit')
    findings, limits = set(), set()
    if len(data) > max_bytes:
        limits.add('file_size')
        data = data[:max_bytes]
    queue = deque([(data, 0, 'literal')])
    seen = {data}
    scheduled, processed = 1, 0
    while queue:
        chunk, depth, route = queue.popleft()
        processed += 1
        for name, marker in markers.items():
            if marker.encode('utf-8') in chunk:
                findings.add((name, route))
        for candidate in TOKEN.finditer(chunk):
            token = candidate.group()
            try:
                decoded = base64.b64decode(token + b'=' * (-len(token) % 4),
                                           altchars=b'-_', validate=True)
            except (binascii.Error, ValueError):
                continue
            # Only expand textual candidates. Binary/encrypted payloads are not covered.
            if not decoded or decoded in seen:
                continue
            try:
                decoded.decode('utf-8')
            except UnicodeDecodeError:
                continue
            if depth >= max_depth:
                limits.add('depth')
                continue
            if scheduled >= max_nodes:
                limits.add('nodes')
                continue
            seen.add(decoded)
            scheduled += 1
            queue.append((decoded, depth + 1, 'base64_depth_' + str(depth + 1)))
    return {'marcadores_PII': sorted({name for name, _ in findings}),
            'hallazgos': [{'marcador': name, 'via': route} for name, route in sorted(findings)],
            'escaneo_acotado_completo': not limits, 'limites_alcanzados': sorted(limits),
            'nodos_inspeccionados': processed}
