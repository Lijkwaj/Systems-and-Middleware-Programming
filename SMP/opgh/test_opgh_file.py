import unittest


class FileTest(unittest.TestCase):
    def test_file(self):
        import opgh
        self.assertIsNotNone(opgh.normalize_ip)
