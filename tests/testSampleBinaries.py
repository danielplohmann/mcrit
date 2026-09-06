import json
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import falcon
import falcon.testing

from mcrit.client.McritClient import McritClient
from mcrit.server.SampleResource import SampleResource
from mcrit.Worker import Worker

from .context import config


class BinaryRouteTest(unittest.TestCase):
    """#95: /samples/{id}/binary answers the raw submission when the instance kept it"""

    @staticmethod
    def _request():
        return falcon.Request(falcon.testing.create_environ(path="/samples/1/binary"))

    def test_the_stored_binary_is_served_as_octets(self):
        index = MagicMock()
        index.isSampleId.return_value = True
        index.getSampleBinary.return_value = b"MZ\x90\x00binary"
        resp = falcon.Response()
        SampleResource(index).on_get_binary(self._request(), resp, 1)
        self.assertEqual(b"MZ\x90\x00binary", resp.data)
        self.assertEqual("application/octet-stream", resp.content_type)

    def test_an_unknown_sample_and_a_sample_without_binary_are_404(self):
        index = MagicMock()
        index.isSampleId.return_value = False
        resp = falcon.Response()
        SampleResource(index).on_get_binary(self._request(), resp, 1)
        self.assertEqual(falcon.HTTP_404, resp.status)
        index.isSampleId.return_value = True
        index.getSampleBinary.return_value = None
        resp = falcon.Response()
        SampleResource(index).on_get_binary(self._request(), resp, 1)
        self.assertEqual(falcon.HTTP_404, resp.status)
        assert resp.data is not None
        self.assertEqual("failed", json.loads(resp.data)["status"])


class BinaryClientTest(unittest.TestCase):
    def test_the_client_hands_out_the_bytes_or_none(self):
        client = McritClient("http://mcrit.test")
        with patch("mcrit.client.McritClient.requests.get", return_value=MagicMock(status_code=200, content=b"bytes")) as get:
            self.assertEqual(b"bytes", client.getSampleBinary(3))
            self.assertIn("/samples/3/binary", get.call_args.args[0])
        with patch("mcrit.client.McritClient.requests.get", return_value=MagicMock(status_code=404)):
            self.assertIsNone(client.getSampleBinary(3))


class WorkerKeepsBinariesTest(unittest.TestCase):
    def _worker(self, keep):
        storage = MagicMock()
        storage.getSampleBySha256.return_value = None
        storage.storeSampleBinary.return_value = True
        worker = Worker(queue=MagicMock(), config=config, storage=storage)
        worker._storage_config = SimpleNamespace(STORAGE_KEEP_SUBMITTED_BINARIES=keep, STORAGE_MONGODB_CLEANUP_TTL=1)
        sample_entry = MagicMock()
        sample_entry.sample_id = 42
        sample_entry.toDict.return_value = {"sample_id": 42}
        setattr(worker, "_addReport", lambda report: sample_entry)
        return worker, storage

    def test_the_binary_is_kept_only_when_configured(self):
        with patch("mcrit.Worker.Disassembler") as disassembler:
            disassembler.return_value.disassembleUnmappedBuffer.return_value = MagicMock()
            worker, storage = self._worker(keep=True)
            result = worker.addBinarySample(b"MZ", "a.exe", "fam", "1", False, None, None)
            storage.storeSampleBinary.assert_called_once_with(42, b"MZ")
            self.assertTrue(result["binary_stored"])
            worker, storage = self._worker(keep=False)
            result = worker.addBinarySample(b"MZ", "a.exe", "fam", "1", False, None, None)
            storage.storeSampleBinary.assert_not_called()
            self.assertNotIn("binary_stored", result)

    def test_a_known_sample_without_a_stored_binary_gets_it_on_resubmission(self):
        """a retried job (sample committed, binary not) or a sample from before binaries were
        kept: the existing-sample path completes the storage instead of skipping it"""
        with patch("mcrit.Worker.Disassembler"):
            worker, storage = self._worker(keep=True)
            known = MagicMock()
            known.sample_id = 7
            known.toDict.return_value = {"sample_id": 7}
            storage.getSampleBySha256.return_value = known
            storage.getSampleBinary.return_value = None
            result = worker.addBinarySample(b"MZ", "a.exe", "fam", "1", False, None, None)
            storage.storeSampleBinary.assert_called_once_with(7, b"MZ")
            self.assertTrue(result["binary_stored"])
            # already stored: nothing to do
            storage.storeSampleBinary.reset_mock()
            storage.getSampleBinary.return_value = b"MZ"
            result = worker.addBinarySample(b"MZ", "a.exe", "fam", "1", False, None, None)
            storage.storeSampleBinary.assert_not_called()
            self.assertNotIn("binary_stored", result)


if __name__ == "__main__":
    unittest.main()
