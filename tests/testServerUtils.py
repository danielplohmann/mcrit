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
        req_params = {
            "pichash_size": "-1",
            "minhash_score": "150",
            "band_matches_required": "-5"
        }
        expected = {
            "pichash_size": 0,
            "minhash_threshold": 100,
            "band_matches_required": 0
        }
        self.assertEqual(getMatchingParams(req_params), expected)

        req_params = {
            "minhash_score": "-10"
        }
        expected = {
            "minhash_threshold": 0
        }
        self.assertEqual(getMatchingParams(req_params), expected)

    @patch("mcrit.server.utils.LOGGER")
    def test_getMatchingParams_invalid_pichash_size(self, mock_logger):
        req_params = {"pichash_size": "not-an-int"}
        result = getMatchingParams(req_params)
        self.assertEqual(result, {})
        mock_logger.warning.assert_called_with("Failed to handle request parameter: pichash_size: not-an-int")

    @patch("mcrit.server.utils.LOGGER")
    def test_getMatchingParams_invalid_minhash_score(self, mock_logger):
        req_params = {"minhash_score": "not-an-int"}
        result = getMatchingParams(req_params)
        self.assertEqual(result, {})
        mock_logger.warning.assert_called_with("Failed to handle request parameter: minhash_score: not-an-int")

    @patch("mcrit.server.utils.LOGGER")
    def test_getMatchingParams_invalid_band_matches_required(self, mock_logger):
        req_params = {"band_matches_required": "not-an-int"}
        result = getMatchingParams(req_params)
        self.assertEqual(result, {})
        mock_logger.warning.assert_called_with("Failed to handle request parameter: band_matches_required: not-an-int")

if __name__ == "__main__":
    unittest.main()
