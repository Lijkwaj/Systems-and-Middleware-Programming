import unittest
import opgh


class SessionMessagesTestCase(unittest.TestCase):
    def test_messages_monologue(self):
        log_entries = [
            {
                "src_ip": "145.18.11.151",
                "dest_ip": "145.18.11.73",
                "src_port": 443,
                "dest_port": 443,
                "timestamp": "2022-07-03 12:36:25",
                "msg_no": 0,
                "payload": "Hi!"
            },
            {
                "src_ip": "145.18.11.151",
                "dest_ip": "145.18.11.73",
                "src_port": 443,
                "dest_port": 443,
                "timestamp": "2022-07-03 12:37:59",
                "msg_no": 1,
                "payload": "You there?"
            },
            {
                "src_ip": "145.18.11.151",
                "dest_ip": "145.18.11.201",
                "src_port": 443,
                "dest_port": 443,
                "timestamp": "2022-07-03 12:36:25",
                "msg_no": 0,
                "payload": "Whatsup?"
            }
        ]

        result = opgh.network_session_messages("145.18.11.151", 443, "145.18.11.73", 443, log_entries)

        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 2)
        self.assertIsInstance(result[0], opgh.SessionMessage)
        self.assertIsInstance(result[1], opgh.SessionMessage)

        if result[0].nr == 0:
            msg0 = result[0]
            msg1 = result[1]
        else:
            msg0 = result[1]
            msg1 = result[0]
        
        self.assertEqual(msg0.timestamp, "2022-07-03 12:36:25")
        self.assertEqual(msg0.payload, "Hi!")
        self.assertEqual(msg1.timestamp, "2022-07-03 12:37:59")
        self.assertEqual(msg1.payload, "You there?")

    def test_messages_converstation(self):
        log_entries = [
            {
                "src_ip": "145.18.11.151",
                "dest_ip": "145.18.11.201",
                "src_port": 443,
                "dest_port": 443,
                "timestamp": "2022-07-03 12:33:25",
                "msg_no": 3,
                "payload": "Whatsup?"
            },
            {
                "src_ip": "145.18.11.151",
                "dest_ip": "145.18.11.73",
                "src_port": 443,
                "dest_port": 443,
                "timestamp": "2022-07-03 12:55:13",
                "msg_no": 12,
                "payload": "Luke, I'm your father"
            },
            {
                "src_ip": "145.18.11.73",
                "dest_ip": "145.18.11.151",
                "src_port": 443,
                "dest_port": 443,
                "timestamp": "2022-07-03 12:58:48",
                "msg_no": 17,
                "payload": "May the force be with you!"
            }
        ]

        result = opgh.network_session_messages("145.18.11.151", 443, "145.18.11.73", 443, log_entries)

        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 2)
        self.assertIsInstance(result[0], opgh.SessionMessage)
        self.assertIsInstance(result[1], opgh.SessionMessage)
        self.assertTrue(result[0].nr == 12 or result[0].nr == 17)
        if result[0].nr == 12:
            msg0 = result[0]
            msg1 = result[1]
        else:
            msg0 = result[1]
            msg1 = result[0]
        
        self.assertEqual(msg0.timestamp, "2022-07-03 12:55:13")
        self.assertEqual(msg0.payload, "Luke, I'm your father")
        self.assertEqual(msg1.timestamp, "2022-07-03 12:58:48")
        self.assertEqual(msg1.payload, "May the force be with you!")


if __name__ == "__main__":
    unittest.main()
