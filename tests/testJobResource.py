import json
import unittest
from unittest.mock import MagicMock

import falcon
import falcon.testing

from mcrit.index.MinHashIndex import MinHashIndex
from mcrit.server.JobResource import JobResource

from .context import config

RESULT = {"matches": {"functions": [[1, 2, 3]], "samples": [[4, 5]]}, "info": {"job": {"parameters": "x"}}}
STORED = json.dumps(RESULT).encode("ascii")
JOB_ID = "0123456789abcdef01234567"
RESULT_ID = "fedcba9876543210fedcba98"
MATCHING_JOB = {"payload": {"method": "getMatchesForSample", "params": "[7]"}, "_id": JOB_ID}


class ResultRoutesServeTheStoredBytes(unittest.TestCase):
    """A stored result is JSON already; the routes put its bytes into the envelope instead of
    parsing and re-serialising them (#152), except for compact, which has to edit the dict."""

    @staticmethod
    def _request(query_string=""):
        return falcon.Request(falcon.testing.create_environ(path="/jobs", query_string=query_string))

    def _resource(self, stored=STORED, job_data=MATCHING_JOB):
        index = MagicMock()
        index.getJobData.return_value = job_data
        index.getJobIdForResult.return_value = JOB_ID
        index.getResultBytesForJob.return_value = stored
        index.getResultBytes.return_value = stored
        index.getResultForJob.return_value = json.loads(stored) if stored is not None else None
        index.getResult.return_value = json.loads(stored) if stored is not None else None
        return index, JobResource(index)

    def test_the_job_result_route_passes_the_bytes_through(self):
        index, resource = self._resource()
        resp = falcon.Response()
        resource.on_get_job_result(self._request(), resp, JOB_ID)
        assert resp.data is not None
        self.assertEqual(b'{"status": "successful", "data": ' + STORED + b"}", resp.data)
        self.assertEqual({"status": "successful", "data": RESULT}, json.loads(resp.data))
        index.getResultForJob.assert_not_called()

    def test_the_result_route_passes_the_bytes_through(self):
        index, resource = self._resource()
        resp = falcon.Response()
        resource.on_get_results(self._request(), resp, RESULT_ID)
        assert resp.data is not None
        self.assertEqual({"status": "successful", "data": RESULT}, json.loads(resp.data))
        index.getResultBytes.assert_called_once_with(RESULT_ID)
        index.getResult.assert_not_called()

    def test_compact_still_parses_and_drops_the_function_matches(self):
        for route, argument in ((JobResource.on_get_job_result, JOB_ID), (JobResource.on_get_results, RESULT_ID)):
            index, resource = self._resource()
            resp = falcon.Response()
            route(resource, self._request("compact=true"), resp, argument)
            assert resp.data is not None
            self.assertEqual({"samples": [[4, 5]]}, json.loads(resp.data)["data"]["matches"])
            index.getResultBytesForJob.assert_not_called()
            index.getResultBytes.assert_not_called()

    def test_compact_leaves_a_non_matching_job_alone(self):
        index, resource = self._resource(job_data={"payload": {"method": "getUniqueBlocks", "params": "[[1]]"}, "_id": JOB_ID})
        resp = falcon.Response()
        resource.on_get_job_result(self._request("compact=true"), resp, JOB_ID)
        assert resp.data is not None
        self.assertEqual(RESULT, json.loads(resp.data)["data"])

    def test_a_missing_result_is_still_null(self):
        for query in ("", "compact=true"):
            index, resource = self._resource(stored=None)
            resp = falcon.Response()
            resource.on_get_job_result(self._request(query), resp, JOB_ID)
            assert resp.data is not None
            self.assertEqual({"status": "successful", "data": None}, json.loads(resp.data))

    def test_an_invalid_id_is_rejected_before_any_lookup(self):
        index, resource = self._resource()
        resp = falcon.Response()
        resource.on_get_job_result(self._request(), resp, "nope")
        self.assertEqual(falcon.HTTP_400, resp.status)
        index.getResultBytesForJob.assert_not_called()


class StoredBytesAccessors(unittest.TestCase):
    def test_the_index_hands_out_the_bytes_the_result_was_stored_with(self):
        index = MinHashIndex(config)
        result_id = index.queue._dicts_to_grid(RESULT, metadata={"result": True, "job": "none"})
        self.assertEqual(STORED, index.getResultBytes(result_id))
        self.assertEqual(RESULT, index.getResult(result_id))
        self.assertIsNone(index.getResultBytesForJob("0123456789abcdef01234567"))


if __name__ == "__main__":
    unittest.main()
