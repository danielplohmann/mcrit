import logging
import os
import unittest

from mcrit.server import api_reference

logging.disable(logging.CRITICAL)


class ApiReferenceTest(unittest.TestCase):
    """docs/api_reference.md is generated from the route table (#54): it must match the code and
    every responder must carry a docstring for it to describe"""

    def setUp(self):
        from mcrit.server.application_routes import get_app

        self.entries = api_reference.routes(get_app())

    def test_every_route_is_documented(self):
        undocumented = ["%s %s" % (entry["method"], entry["path"]) for entry in self.entries if not entry["doc"]]
        self.assertEqual([], undocumented)
        self.assertGreaterEqual(len(self.entries), 54)

    def test_the_client_is_cross_referenced(self):
        by_route = {(entry["method"], entry["path"]): entry["clients"] for entry in self.entries}
        self.assertEqual(["getFamily", "isFamilyId"], by_route[("GET", "/families/{family_id:int}")])
        self.assertEqual(["getMatchesForPicHash"], by_route[("GET", "/query/pichash/{pichash}/summary")])
        self.assertEqual(["search_families"], by_route[("GET", "/search/families")])
        self.assertEqual(["search_functions"], by_route[("GET", "/search/functions")])
        self.assertEqual(["deleteQueueData"], by_route[("DELETE", "/jobs")])
        self.assertEqual(["deleteJob"], by_route[("DELETE", "/jobs/{job_id}")])
        # only endpoints without a client method may be left blank
        self.assertEqual(
            ["GET /", "GET /config", "GET /matches/function/{function_id:int}", "GET /samples/{sample_id:int}/functions/{function_id:int}"],
            sorted("%s %s" % (entry["method"], entry["path"]) for entry in self.entries if not entry["clients"]),
        )

    def test_the_committed_reference_is_current(self):
        with open(api_reference.DEFAULT_OUTPUT) as handle:
            committed = handle.read()
        self.assertEqual(api_reference.render(self.entries), committed, "docs/api_reference.md is stale: python -m mcrit.server.api_reference")
        self.assertTrue(os.path.exists(api_reference.CLIENT_SOURCE))


if __name__ == "__main__":
    unittest.main()
