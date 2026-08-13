import unittest

from mcrit.queue.QueueRemoteCalls import from_binary, to_binary


class TestQueueRemoteCallsUtils(unittest.TestCase):
    def test_to_binary_simple(self):
        result = to_binary({"a": 1, "b": 2})
        self.assertIsInstance(result, bytes)
        self.assertEqual(result, b'{"a": 1, "b": 2}')

    def test_to_binary_nested(self):
        result = to_binary({"c": [3, 2, 1], "a": {"z": 1, "y": 2}})
        self.assertEqual(result, b'{"a": {"y": 2, "z": 1}, "c": [3, 2, 1]}')

    def test_to_binary_sort_keys(self):
        # keys are sorted, so that identical payloads produce identical binaries
        result = to_binary({"z": 1, "a": 2, "m": 3})
        self.assertEqual(result, b'{"a": 2, "m": 3, "z": 1}')

    def test_to_binary_non_ascii(self):
        # ensure_ascii is the json default, so non-ascii characters are escaped
        result = to_binary({"euro": "€"})
        self.assertEqual(result, b'{"euro": "\\u20ac"}')

    def test_to_binary_empty(self):
        self.assertEqual(to_binary({}), b"{}")

    def test_to_binary_none(self):
        self.assertEqual(to_binary(None), b"null")

    def test_from_binary(self):
        self.assertEqual(from_binary(b'{"a": 1, "b": 2}'), {"a": 1, "b": 2})

    def test_from_binary_empty(self):
        self.assertEqual(from_binary(b"{}"), {})

    def test_from_binary_none(self):
        self.assertIsNone(from_binary(b"null"))

    def test_roundtrip(self):
        data = {"complex": [1, 2, {"three": 3}], "another": "value"}
        self.assertEqual(from_binary(to_binary(data)), data)


if __name__ == "__main__":
    unittest.main()
