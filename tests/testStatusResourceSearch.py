import json
import unittest
from unittest.mock import MagicMock

import falcon
import falcon.testing

from mcrit.server.StatusResource import StatusResource

SEARCH_ENDPOINTS = [
    ("on_get_search_families", "getFamilySearchResults", "/search/families"),
    ("on_get_search_samples", "getSampleSearchResults", "/search/samples"),
    ("on_get_search_functions", "getFunctionSearchResults", "/search/functions"),
]


class TestStatusResourceSearch(unittest.TestCase):
    @staticmethod
    def _request(path, query_string):
        return falcon.Request(falcon.testing.create_environ(path=path, query_string=query_string))

    def test_unsupported_search_is_answered_as_a_client_error(self):
        # a field, operator or sort field the backend cannot serve used to escape the responder
        # and become a 500 with a traceback
        for endpoint, search_method, path in SEARCH_ENDPOINTS:
            with self.subTest(endpoint=endpoint):
                index = MagicMock()
                getattr(index, search_method).side_effect = ValueError("Sorting by the field 'pichash' is not supported by the MongoDB backend.")
                resp = falcon.Response()
                getattr(StatusResource(index), endpoint)(self._request(path, "query=foo&sort_by=pichash"), resp)
                self.assertEqual(falcon.HTTP_400, resp.status)
                payload = json.loads(resp.data)
                self.assertEqual("failed", payload["status"])
                self.assertIn("pichash", payload["data"]["message"])

    def test_search_results_are_passed_through(self):
        for endpoint, search_method, path in SEARCH_ENDPOINTS:
            with self.subTest(endpoint=endpoint):
                index = MagicMock()
                getattr(index, search_method).return_value = {"search_results": {}}
                resp = falcon.Response()
                getattr(StatusResource(index), endpoint)(self._request(path, "query=foo"), resp)
                self.assertEqual(falcon.HTTP_200, resp.status)
                payload = json.loads(resp.data)
                self.assertEqual("successful", payload["status"])
                self.assertEqual({"search_results": {}}, payload["data"])


if __name__ == "__main__":
    unittest.main()
