import os
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import vm_queue as queue


class ServiceQueueTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {'REMOTEX_VM_QUEUE_FILE': str(Path(self.temp.name) / 'queue.json')})
        self.env.start()
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(self.env.stop)
        self.host = 'gitlab:host:238'
        self.a = self.host + '::service::observer'
        self.b = self.host + '::service::website'

    def test_services_parallel_but_host_exclusive(self):
        self.assertTrue(queue.claim(self.a, 'alice', True)['claimed'])
        self.assertTrue(queue.claim(self.b, 'bob', True)['claimed'])
        self.assertFalse(queue.claim(self.host, 'ops', True)['claimed'])
        queue.release(self.a, 'alice')
        self.assertFalse(queue.claim(self.host, 'ops', True)['claimed'])
        queue.release(self.b, 'bob')
        self.assertTrue(queue.claim(self.host, 'ops', True)['claimed'])
        self.assertFalse(queue.claim(self.a, 'alice', True)['claimed'])

    def test_waiting_maintenance_prevents_new_service_starvation(self):
        queue.claim(self.a, 'alice', True)
        queue.request(self.host, 'ops')
        self.assertFalse(queue.inspect(self.b, 'bob')['claim_available'])
        self.assertFalse(queue.claim(self.b, 'bob', True)['claimed'])
        queue.require_owner(self.a, 'alice')
        queue.release(self.a, 'alice')
        queue.claim(self.host, 'ops', True)
        queue.release(self.host, 'ops')
        self.assertTrue(queue.claim(self.b, 'bob', True)['claimed'])

    def test_same_service_fifo_and_unrelated_hosts(self):
        queue.claim(self.a, 'alice', True)
        queue.request(self.a, 'bob')
        queue.request(self.a, 'charlie')
        queue.release(self.a, 'alice')
        self.assertFalse(queue.claim(self.a, 'charlie', True)['claimed'])
        self.assertTrue(queue.claim(self.a, 'bob', True)['claimed'])
        self.assertTrue(queue.claim('other::service::observer', 'elsewhere', True)['claimed'])

    def test_parent_child_race_only_one_wins(self):
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda args: queue.claim(*args, True),
                                    [(self.host, 'ops'), (self.a, 'alice')]))
        self.assertEqual(sum(result['claimed'] for result in results), 1)

    def test_same_requester_cannot_hold_parent_and_child(self):
        queue.claim(self.host, 'ops', True)
        self.assertFalse(queue.claim(self.a, 'ops', True)['claimed'])

    def test_malformed_scopes_rejected(self):
        for value in [self.host + '::service::', self.a + '::service::nested', '::service::a']:
            with self.subTest(value=value), self.assertRaises(Exception):
                queue.claim(value, 'alice', True)

    def test_scoped_state_requires_new_reader_even_after_release(self):
        queue.claim(self.a, 'alice', True)
        self.assertEqual(json.loads(queue.queue_path().read_text())['version'], 2)
        queue.release(self.a, 'alice')
        self.assertEqual(json.loads(queue.queue_path().read_text())['version'], 2)

    def test_conflicting_persisted_owners_fail_closed(self):
        queue.claim(self.host, 'ops', True)
        state = json.loads(queue.queue_path().read_text())
        state['version'] = 2
        state['resources'][self.a] = {'owner': {'requester': 'alice', 'claimed_at': '2026-09-20T00:00:00Z'}, 'waiters': []}
        queue.queue_path().write_text(json.dumps(state))
        with self.assertRaisesRegex(Exception, 'Conflicting'):
            queue.require_owner(self.host, 'ops')

    def test_v1_service_record_is_not_treated_as_safe_ownership(self):
        state = {'version': 1, 'resources': {self.a: {
            'owner': {'requester': 'alice', 'claimed_at': '2026-09-20T00:00:00Z'}, 'waiters': []}}}
        queue.queue_path().write_text(json.dumps(state))
        with self.assertRaisesRegex(Exception, 'version 2'):
            queue.require_owner(self.a, 'alice')


if __name__ == '__main__':
    unittest.main()
