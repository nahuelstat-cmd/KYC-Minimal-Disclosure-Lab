"""Regression: keep connections alive to expose leaked SQLite file handles."""
import sqlite3
import io
from contextlib import redirect_stdout
import tempfile
import unittest
from pathlib import Path, PureWindowsPath
from unittest.mock import patch
import demo_minimizacion
import reference_jws

class TrackedConnection(sqlite3.Connection):
    closed_explicitly = False

    def close(self):
        super().close()
        self.closed_explicitly = True

class ConnectionCleanupTests(unittest.TestCase):
    def test_complete_flow_closes_every_connection(self):
        original_connect = sqlite3.connect
        connections = []

        def tracked_connect(*args, **kwargs):
            kwargs['factory'] = TrackedConnection
            connection = original_connect(*args, **kwargs)
            connections.append(connection)  # Prevent GC from hiding a leak.
            return connection

        try:
            with patch.object(sqlite3, 'connect', side_effect=tracked_connect):
                demo_minimizacion.main()
            self.assertGreater(len(connections), 0)
            self.assertTrue(all(c.closed_explicitly for c in connections),
                            'A SQLite connection was not explicitly closed')
        finally:
            for connection in connections:
                connection.close()

    def test_audit_normalizes_windows_paths(self):
        class WindowsFile:
            def is_file(self): return True
            def read_bytes(self): return b'fixture'
            def relative_to(self, root):
                return PureWindowsPath('proveedor/evidencia.json')
        class FakeRoot:
            def rglob(self, pattern): return [WindowsFile()]
        records = demo_minimizacion.audit(FakeRoot())
        self.assertEqual(records[0]['archivo'], 'proveedor/evidencia.json')
        self.assertTrue(records[0]['archivo'].startswith('proveedor/'))

    def test_failed_control_has_no_success_message(self):
        security = reference_jws.run()
        security['status'] = 'FAIL'
        output = io.StringIO()
        with patch.object(demo_minimizacion, 'security_checks', return_value=security):
            with redirect_stdout(output):
                with self.assertRaisesRegex(RuntimeError, 'controles_JWS_21'):
                    demo_minimizacion.main()
        self.assertIn('Controles fallidos: controles_JWS_21', output.getvalue())
        self.assertNotIn('presentes en proveedor; ausentes', output.getvalue())

    def test_transaction_commit_and_rollback(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'transaction.sqlite'
            with reference_jws.db_connection(path) as conn:
                conn.execute('CREATE TABLE sample(value INTEGER)')
                conn.execute('INSERT INTO sample VALUES (1)')
            with self.assertRaises(sqlite3.ProgrammingError):
                conn.execute('SELECT 1')
            with self.assertRaises(ValueError):
                with reference_jws.db_connection(path) as failed:
                    failed.execute('INSERT INTO sample VALUES (2)')
                    raise ValueError('simulated failure')
            with self.assertRaises(sqlite3.ProgrammingError):
                failed.execute('SELECT 1')
            with reference_jws.db_connection(path) as check:
                self.assertEqual(check.execute('SELECT value FROM sample').fetchall(), [(1,)])

if __name__ == '__main__':
    unittest.main()
