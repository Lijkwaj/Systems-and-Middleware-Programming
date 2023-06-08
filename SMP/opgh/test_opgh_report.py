import unittest
import opgh


SUSPICIOUS_ACTIVITY_DB = {
    "office_hours_start": "07:00",
    "office_hours_end": "18:00",
    "payloads": ["pen-test", "66"],
    "host_pairs": [("145.18.11.151", "115.105.116.104"), ("145.18.11.151", "192.168.4.1")]
}


class ReportUnitTest(unittest.TestCase):
    def test_report(self):
        sessions = [
            opgh.NetworkSession(
                "145.18.11.151", 443,
                "115.105.116.104", 443,
                [opgh.SessionMessage(5, "2022-07-03 12:36:25", "Death Star"),
                opgh.SessionMessage(6, "2022-07-03 12:36:26", "Weakpoint")]
            ),
            opgh.NetworkSession(
                "145.18.11.151", 443,
                "127.0.0.1", 443,
                [opgh.SessionMessage(5, "2022-07-03 12:36:25", "Hoi!\n")]
            ),
            opgh.NetworkSession(
                "115.105.116.104", 443,
                "145.18.11.151", 443,
                [opgh.SessionMessage(2, "2022-07-03 03:36:25", "Hi"),
                opgh.SessionMessage(3, "2022-07-03 05:36:25", "Wat heb je nodig om je eigen pen-test te schrijven?\n"),
                opgh.SessionMessage(5, "2022-07-03 12:36:25", "Execute order 66"),
                opgh.SessionMessage(6, "2022-07-03 12:36:25", "Bye")]
            )
        ]

        expected_session_report_1 = """Network Session Report
145.18.11.151:443 -> 115.105.116.104:443
From 2022-07-03 12:36:25 to 2022-07-03 12:36:26 2 message(s) were sent
Flagged because:
- Hosts 145.18.11.151 and 115.105.116.104 not allowed to communicate"""

        expected_session_report_2 = """Network Session Report
145.18.11.151:443 -> 127.0.0.1:443
From 2022-07-03 12:36:25 to 2022-07-03 12:36:25 1 message(s) were sent
Found nothing suspicious"""

        expected_session_report_3 = """Network Session Report
115.105.116.104:443 -> 145.18.11.151:443
From 2022-07-03 03:36:25 to 2022-07-03 12:36:25 4 message(s) were sent
Flagged because:
"""

        result = opgh.generate_report(sessions, SUSPICIOUS_ACTIVITY_DB)
        result = result.strip()
        
        self.assertIsInstance(result, str)
        results = result.split("\n\n")
        
        self.assertEqual(len(results), 4)
        self.assertEqual(results[0], "Network data report")

        for result in results[1:]:
            if "2 message(s)" in result:
                self.assertEqual(result, expected_session_report_1)
            elif "1 message(s)" in result:
                self.assertEqual(result, expected_session_report_2)
            else:
                self.assertIn(expected_session_report_3, result)
                self.assertIn("- Hosts 115.105.116.104 and 145.18.11.151 not allowed to communicate", result)
                self.assertIn("- Suspicious payload 'pen-test' in message 3", result)
                self.assertIn("- Suspicious payload '66' in message 5", result)
                self.assertIn("- Communication outside office hours", result)


if __name__ == "__main__":
    unittest.main()
