import json
import os
from pathlib import Path
import tempfile
import unittest


class StateTests(unittest.TestCase):
    def test_atomic_save_returns_the_digest_of_persisted_bytes(self):
        from reviewer import state
        import hashlib
        with tempfile.TemporaryDirectory(dir=os.environ.get('ICR_TEST_SCRATCH')) as d:
            path = Path(d) / 'record.json'
            digest = state.save_atomic(path, {'message': '你好', 'count': 1})
            self.assertEqual(json.loads(path.read_text(encoding='utf-8')), {'message': '你好', 'count': 1})
            self.assertEqual(digest, hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertEqual([p.name for p in Path(d).iterdir()], ['record.json'])

    def test_claim_never_replaces_an_existing_owner(self):
        from reviewer import state
        with tempfile.TemporaryDirectory(dir=os.environ.get('ICR_TEST_SCRATCH')) as d:
            path = Path(d) / 'lane.lock'
            first = state.claim(path, {'run_id': 'first'})
            with self.assertRaisesRegex(RuntimeError, 'NOT_AUTHORIZED'):
                state.claim(path, {'run_id': 'second'})
            self.assertEqual(json.loads(path.read_text(encoding='utf-8'))['run_id'], 'first')
            self.assertEqual(first['run_id'], 'first')

    def test_nonfinite_records_are_rejected_before_replacing_good_data(self):
        from reviewer import state
        with tempfile.TemporaryDirectory(dir=os.environ.get('ICR_TEST_SCRATCH')) as d:
            path = Path(d) / 'record.json'
            state.save_atomic(path, {'count': 1})
            with self.assertRaises(ValueError):
                state.save_atomic(path, {'count': float('nan')})
            self.assertEqual(json.loads(path.read_text(encoding='utf-8')), {'count': 1})


if __name__ == '__main__':
    unittest.main()
