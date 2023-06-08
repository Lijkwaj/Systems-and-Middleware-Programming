import unittest
import opgh


class NormalizeSourceDestinationTestCase(unittest.TestCase):
    def test_src_ip(self):
        malformed_log_entry = {
            "source": "145.18.11.151:443",
            "dest_ip": "127.0.0.1",
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
        
        result = opgh.normalize_source_and_destination(malformed_log_entry)
        self.assertEqual(result, expected_log_entry)

        # check if nothing gets changed if nothing is supposed to change
        result = opgh.normalize_source_and_destination(result)
        self.assertEqual(result, expected_log_entry)
    
    def test_dest_ip(self):
        malformed_log_entry = {
            "src_ip": "145.18.11.151",
            "destination": "127.0.0.1:443",
            "src_port": 443,
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
        
        result = opgh.normalize_source_and_destination(malformed_log_entry)
        self.assertEqual(result, expected_log_entry)

        # check if nothing gets changed if nothing is supposed to change
        result = opgh.normalize_source_and_destination(result)
        self.assertEqual(result, expected_log_entry)


if __name__ == "__main__":
    unittest.main()
