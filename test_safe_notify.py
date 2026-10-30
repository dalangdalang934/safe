import tempfile
import unittest
from safe_notify import notification_for, read_new_matches


class NotificationTest(unittest.TestCase):
    def test_only_new_results_with_score_at_least_11_trigger_messages(self):
        self.assertIsNone(notification_for({'score': 10, 'saltNonce': '2'}, '1'))
        self.assertIsNone(notification_for({'score': 11, 'saltNonce': '1'}, '1'))
        message = notification_for({
            'score': 11,
            'saltNonce': '2',
            'address': '0xddddddddddd621f474bdd51b0473ebf28b93cf03',
        }, '1')
        self.assertIn('11', message)
        self.assertIn('0xddddddddddd621f474bdd51b0473ebf28b93cf03', message)
        self.assertIn('2', message)

    def test_reads_every_new_jsonl_match_including_equal_scores(self):
        with tempfile.NamedTemporaryFile() as f:
            f.write(b'{"score": 12, "saltNonce": "1", "address": "0x1234"}\n')
            f.flush()
            matches, offset = read_new_matches(f.name, 0)
            self.assertEqual(len(matches), 1)
            f.write(b'{"score": 12, "saltNonce": "2", "address": "0x1234"}\n{"score": 13, "saltNonce": "3", "address": "0x1234"}\n')
            f.flush()
            matches, offset = read_new_matches(f.name, offset)
            self.assertEqual([m['saltNonce'] for m in matches], ['2', '3'])
            self.assertIsNotNone(notification_for(matches[0], None))


if __name__ == '__main__':
    unittest.main()
