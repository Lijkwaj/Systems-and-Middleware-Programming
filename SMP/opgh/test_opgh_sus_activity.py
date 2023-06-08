import unittest
import opgh

SUSPICIOUS_ACTIVITY_DB = {
    "office_hours_start": "07:00",
    "office_hours_end": "18:00",
    "payloads": ["pen-test", "66"],
    "host_pairs": [("145.18.11.151", "115.105.116.104"), ("145.18.11.151", "192.168.4.1")]
}


class SuspciousActivityUnitTest(unittest.TestCase):
    def test_hosts(self):
        session = opgh.NetworkSession(
            "145.18.11.151", 443,
            "115.105.116.104", 443,
            [opgh.SessionMessage(5, "2022-07-03 12:36:25", "Death Star")]
        )

        results = session.detect_suspicious_activity(SUSPICIOUS_ACTIVITY_DB)
        self.assertIsInstance(results, list)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0], "Hosts 145.18.11.151 and 115.105.116.104 not allowed to communicate")
    
    def test_payload(self):
        session = opgh.NetworkSession(
            "145.18.11.151", 443,
            "127.0.0.1", 443,
            [opgh.SessionMessage(5, "2022-07-03 12:36:25", "Wat heb je nodig om je eigen pen-test te schrijven?\n")]
        )

        results = session.detect_suspicious_activity(SUSPICIOUS_ACTIVITY_DB)

        self.assertIsInstance(results, list)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0], "Suspicious payload 'pen-test' in message 5")
    
    def test_time(self):
        session = opgh.NetworkSession(
            "192.168.4.1", 443,
            "115.105.116.104", 443,
            [opgh.SessionMessage(2, "2022-07-03 03:36:25", "Hi"),
             opgh.SessionMessage(6, "2022-07-03 12:36:25", "Bye")]
        )

        results = session.detect_suspicious_activity(SUSPICIOUS_ACTIVITY_DB)
        self.assertIsInstance(results, list)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0], "Communication outside office hours")

    def test_combi(self):
        session = opgh.NetworkSession(
            "115.105.116.104", 443,
            "145.18.11.151", 443,
            [opgh.SessionMessage(2, "2022-07-03 03:36:25", "Hi"),
            opgh.SessionMessage(3, "2022-07-03 05:36:25", "Wat heb je nodig om je eigen pen-test te schrijven?"),
            opgh.SessionMessage(5, "2022-07-03 12:36:25", "Execute order 66"),
            opgh.SessionMessage(6, "2022-07-03 12:36:25", "Bye")]
        )

        results = session.detect_suspicious_activity(SUSPICIOUS_ACTIVITY_DB)

        self.assertIsInstance(results, list)
        self.assertEqual(len(results), 4)
        self.assertIn("Hosts 115.105.116.104 and 145.18.11.151 not allowed to communicate", results)
        self.assertIn("Suspicious payload 'pen-test' in message 3", results)
        self.assertIn("Suspicious payload '66' in message 5", results)
        self.assertIn("Communication outside office hours", results)


if __name__ == "__main__":
    unittest.main()
