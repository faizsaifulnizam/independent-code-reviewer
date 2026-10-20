import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

SCRATCH = os.environ.get('ICR_TEST_SCRATCH')


class ProcessTests(unittest.TestCase):
    def test_real_process_unicode_and_closed_stdin(self):
        from reviewer.cli import run_process
        raw = run_process([sys.executable, '-c', "import sys; print('你好'); assert sys.stdin.read()==''"],
                          time.monotonic()+5, 1000)
        self.assertEqual(raw.decode('utf-8').strip(), '你好')

    def test_real_process_output_is_bounded(self):
        from reviewer.cli import run_process
        with self.assertRaisesRegex(RuntimeError, 'PAYLOAD_LIMIT'):
            run_process([sys.executable, '-c', "import sys; sys.stdout.write('x'*100000)"],
                        time.monotonic()+5, 1000)

    def test_real_process_deadline_terminates_owned_child(self):
        from reviewer.cli import run_process
        started = time.monotonic()
        with self.assertRaisesRegex(RuntimeError, 'TIME_BUDGET'):
            run_process([sys.executable, '-c', 'import time; time.sleep(20)'],
                        started+0.3, 1000)
        self.assertLess(time.monotonic()-started, 4)

    def test_entrypoint_invalid_request_from_unrelated_cwd(self):
        import os
        root = str(Path(__file__).resolve().parents[1])
        with tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
            request = Path(directory)/'request.json'
            request.write_text('{"schema_version":"0.2","repository_id":true}', encoding='utf-8')
            env = dict(os.environ, PYTHONPATH=root, PYTHONIOENCODING='utf-8')
            result = subprocess.run([sys.executable, '-m', 'reviewer.cli', 'draft',
                                    '--request', str(request), '--output', str(Path(directory)/'out'),
                                    '--control-repository', 'owner/repo'],
                                   cwd=directory, env=env, stdin=subprocess.DEVNULL,
                                   capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, b'')
            self.assertNotIn(directory.encode(), result.stderr)
            self.assertFalse((Path(directory)/'out').exists())


if __name__ == '__main__':
    unittest.main()
