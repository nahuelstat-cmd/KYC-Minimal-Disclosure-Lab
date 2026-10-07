"""Regression: keep connections alive to expose leaked SQLite file handles."""
import sqlite3
import tempfile
import unittest
from pathlib import Path
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
