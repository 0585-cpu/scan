import unittest

from netprobe.ports import PortParseError, parse_ports


class PortTests(unittest.TestCase):
    def test_parse_ports_single_ranges_and_dedupe(self):
        self.assertEqual(parse_ports("80,443,8000-8002,80"), [80, 443, 8000, 8001, 8002])

    def test_parse_ports_rejects_invalid_range(self):
        with self.assertRaises(PortParseError):
            parse_ports("10-1")

    def test_parse_ports_rejects_out_of_range_port(self):
        with self.assertRaises(PortParseError):
            parse_ports("0")


if __name__ == "__main__":
    unittest.main()
