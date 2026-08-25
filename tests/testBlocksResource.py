import json
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock

import falcon
import falcon.testing

from mcrit.server.BlocksResource import BlocksResource


class TestBlocksResource(unittest.TestCase):
    """#144: the cover's shape is tunable, so the two routes have to pass the parameters on"""

    @staticmethod
    def _request(path, query_string=""):
        return falcon.Request(falcon.testing.create_environ(path=path, query_string=query_string))

    def _resource(self):
        index = MagicMock()
        index.getSamplesByFamilyId.return_value = [SimpleNamespace(sample_id=7), SimpleNamespace(sample_id=8)]
        index.getUniqueBlocks.return_value = {"statistics": {}, "unique_blocks": {}}
        return index, BlocksResource(index)

    def test_samples_route_passes_the_parameters(self):
        index, resource = self._resource()
        resp = falcon.Response()
        resource.on_get_unique_blocks_for_samples(self._request("/uniqueblocks/samples/1,2", "covers_required=3&min_instructions=5"), resp, "1,2")
        index.getUniqueBlocks.assert_called_once_with([1, 2], covers_required=3, min_instructions=5)
        assert resp.data is not None
        self.assertEqual("successful", json.loads(resp.data)["status"])

    def test_family_route_passes_the_parameters(self):
        index, resource = self._resource()
        resource.on_get_unique_blocks_for_family(self._request("/uniqueblocks/family/4", "covers_required=2"), falcon.Response(), 4)
        index.getUniqueBlocks.assert_called_once_with([7, 8], family_id=4, covers_required=2)

    def test_omitted_parameters_leave_the_defaults_to_the_worker(self):
        index, resource = self._resource()
        resource.on_get_unique_blocks_for_samples(self._request("/uniqueblocks/samples/1"), falcon.Response(), "1")
        index.getUniqueBlocks.assert_called_once_with([1])

    def test_malformed_sample_ids_are_not_queried(self):
        index, resource = self._resource()
        resp = falcon.Response()
        resource.on_get_unique_blocks_for_samples(self._request("/uniqueblocks/samples/abc", "covers_required=3"), resp, "abc")
        index.getUniqueBlocks.assert_not_called()
        assert resp.data is not None
        self.assertEqual({}, json.loads(resp.data)["data"])


if __name__ == "__main__":
    unittest.main()
