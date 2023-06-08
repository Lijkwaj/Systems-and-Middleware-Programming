import unittest
import opgh

E1 = "Function network_sessions must return a list"
E2 = "All objects in the returned list must be of the type NetworkSession"
E3 = "Expected session not found"
E4 = "Expected and returned messages in session do not match"
E5 = "Duplicate entry with swapped source and destination ips found"


def contains_messages(messages_ref, messages):
    return all(map(lambda m: (m.nr, m.timestamp, m.payload) in messages_ref, messages))


def contains_session(src_ip, src_port, dest_ip, dest_port, iter):
    def session_check(session):
        return (session.src_ip == src_ip
            and session.src_port == src_port
            and session.dst_ip == dest_ip
            and session.dst_port == dest_port)
    
    return sum(1 for _ in filter(session_check, iter)) == 1


def contains_session_and_messages(src_ip, src_port, dest_ip, dest_port, messages, iter):
    def session_check(session):
        return (session.src_ip == src_ip
            and session.src_port == src_port
            and session.dst_ip == dest_ip
            and session.dst_port == dest_port
            and contains_messages(messages, session.messages))

    return sum(1 for _ in filter(session_check, iter)) == 1


class SessionsTestCase(unittest.TestCase):
    def test_sessions(self):
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
                "dest_ip": "145.18.11.201",
                "src_port": 80,
                "dest_port": 80,
                "timestamp": "2022-07-03 12:36:29",
                "msg_no": 0,
                "payload": "Whatsup?"
            },
            {
                "src_ip": "145.18.11.73",
                "dest_ip": "145.18.11.151",
                "src_port": 443,
                "dest_port": 443,
                "timestamp": "2022-07-03 12:37:59",
                "msg_no": 1,
                "payload": "Yo!"
            }
        ]

        results: list[opgh.NetworkSession] = opgh.network_sessions(log_entries)

        self.assertIsInstance(results, list, E1)
        self.assertTrue(all(map(lambda r: type(r) == opgh.NetworkSession, results)), E2)

        self.assertTrue(contains_session("145.18.11.151", 443, "145.18.11.73", 443, results), E3)
        messages = [(0, "2022-07-03 12:36:25", "Hi!"), (1, "2022-07-03 12:37:59", "Yo!")]
        self.assertTrue(contains_session_and_messages("145.18.11.151", 443, "145.18.11.73", 443, messages, results), E4)

        self.assertTrue(contains_session("145.18.11.151", 80, "145.18.11.201", 80, results), E3)
        messages = [(0, "2022-07-03 12:36:29", "Whatsup?")]
        self.assertTrue(contains_session_and_messages("145.18.11.151", 80, "145.18.11.201", 80, messages, results), E4)

    def test_sessions_no_duplicates(self):
        log_entries = [
            {
                "src_ip": "145.18.11.151",
                "dest_ip": "145.18.11.73",
                "src_port": 443,
                "dest_port": 443,
                "timestamp": "2022-07-03 12:36:25",
                "msg_no": 10,
                "payload": "Hi!"
            },
            {
                "src_ip": "145.18.11.151",
                "dest_ip": "145.18.11.201",
                "src_port": 80,
                "dest_port": 80,
                "timestamp": "2022-07-03 12:36:29",
                "msg_no": 0,
                "payload": "Whatsup?"
            },
            {
                "src_ip": "145.18.11.73",
                "dest_ip": "145.18.11.151",
                "src_port": 443,
                "dest_port": 443,
                "timestamp": "2022-07-03 12:37:59",
                "msg_no": 11,
                "payload": "Yo!"
            }
        ]

        results: list[opgh.NetworkSession] = opgh.network_sessions(log_entries)

        self.assertIsInstance(results, list, E1)
        self.assertTrue(all(map(lambda r: type(r) == opgh.NetworkSession, results)), E2)

        self.assertTrue(contains_session("145.18.11.151", 443, "145.18.11.73", 443, results), E3)
        messages = [(10, "2022-07-03 12:36:25", "Hi!"), (11, "2022-07-03 12:37:59", "Yo!")]
        self.assertTrue(contains_session_and_messages("145.18.11.151", 443, "145.18.11.73", 443, messages, results), E4)

        self.assertTrue(contains_session("145.18.11.151", 80, "145.18.11.201", 80, results), E3)
        messages = [(0, "2022-07-03 12:36:29", "Whatsup?")]
        self.assertTrue(contains_session_and_messages("145.18.11.151", 80, "145.18.11.201", 80, messages, results), E4)
        
        self.assertFalse(contains_session("145.18.11.73", 443, "145.18.11.151", 443, results), E5)
        self.assertEqual(len(results), 2)


if __name__ == "__main__":
    unittest.main()
