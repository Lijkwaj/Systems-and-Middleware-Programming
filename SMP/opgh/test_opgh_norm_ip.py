import unittest
import opgh


class NormalizeIpTestCase(unittest.TestCase):
    def test_src_ip(self):
        malformed_log_entry = {
            "src_ip": "145,18,11,151",
            "dest_ip": "127.0.0.1",
            "src_port": 443,
            "dest_port": 443,
            "timestamp": "2022-07-03 12:36:25",
            "msg_no": "7",
            "payload": " Hi! "
        }
        expected_log_entry = {
            "src_ip": "145.18.11.151",
            "dest_ip": "127.0.0.1",
            "src_port": 443,
            "dest_port": 443,
            "timestamp": "2022-07-03 12:36:25",
            "msg_no": "7",
            "payload": " Hi! "
        }
        
        result = opgh.normalize_ip(malformed_log_entry)
        self.assertEqual(result, expected_log_entry)

        # check if nothing gets changed if nothing is supposed to change
        result = opgh.normalize_ip(result)
        self.assertEqual(result, expected_log_entry)
    
    def test_dest_ip(self):
        malformed_log_entry = {
            "src_ip": "145.18.11.151",
            "dest_ip": "127,0,0,1",
            "src_port": 443,
            "dest_port": 443,
            "timestamp": "2022-07-03 12:36:25",
            "msg_no": "7",
            "payload": " Hi! "
        }
        expected_log_entry = {
            "src_ip": "145.18.11.151",
            "dest_ip": "127.0.0.1",
            "src_port": 443,
            "dest_port": 443,
            "timestamp": "2022-07-03 12:36:25",
            "msg_no": "7",
            "payload": " Hi! "
        }
        
        result = opgh.normalize_ip(malformed_log_entry)
        self.assertEqual(result, expected_log_entry)

        # check if nothing gets changed if nothing is supposed to change
        result = opgh.normalize_ip(result)
        self.assertEqual(result, expected_log_entry)


if __name__ == "__main__":
    unittest.main()
