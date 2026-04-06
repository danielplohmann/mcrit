import unittest
from unittest.mock import patch
from mcrit.server.utils import getMatchingParams

class TestServerUtils(unittest.TestCase):

    def test_getMatchingParams_valid(self):
        req_params = {
            "pichash_size": "8",
            "minhash_score": "50",
            "force_recalculation": "true",
            "sample_group_only": "true",
            "band_matches_required": "3"
        }
        expected = {
            "pichash_size": 8,
            "minhash_threshold": 50,
            "force_recalculation": True,
            "sample_group_only": True,
            "band_matches_required": 3
        }
        self.assertEqual(getMatchingParams(req_params), expected)

    def test_getMatchingParams_edge_cases(self):
        test_cases = [
            (
                "multiple_out_of_bounds",
                {
                    "pichash_size": "-1",
                    "minhash_score": "150",
                    "band_matches_required": "-5",
                },
                {
                    "pichash_size": 0,
                    "minhash_threshold": 100,
                    "band_matches_required": 0,
                },
            ),
            (
                "negative_minhash_score",
                {"minhash_score": "-10"},
                {"minhash_threshold": 0},
            ),
        ]

        for name, req_params, expected in test_cases:
            with self.subTest(msg=name):
                self.assertEqual(getMatchingParams(req_params), expected)

    @patch("mcrit.server.utils.LOGGER")
    def test_getMatchingParams_invalid_integer_params(self, mock_logger):
        invalid_params = [
            "pichash_size",
            "minhash_score",
            "band_matches_required",
        ]
        for param in invalid_params:
            with self.subTest(param=param):
                mock_logger.reset_mock()
                req_params = {param: "not-an-int"}
                result = getMatchingParams(req_params)
                self.assertEqual(result, {})
                mock_logger.warning.assert_called_with(
                    f"Failed to handle request parameter: {param}: not-an-int"
                )

if __name__ == "__main__":
    unittest.main()
