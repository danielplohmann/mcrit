import json
import os
import unittest
from unittest.mock import MagicMock, patch

import falcon
import falcon.testing
from smda.common.SmdaReport import SmdaReport
from smda.SmdaConfig import SmdaConfig

from mcrit.client.McritClient import McritClient
from mcrit.index.MinHashIndex import MinHashIndex
from mcrit.server.StatusResource import StatusResource
from mcrit.Worker import Worker

from .context import config

EXAMPLE_REPORT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "example_report.smda")


class SelectiveMinHashRepair(unittest.TestCase):
    """#142: only the samples an older escaper hashed are rehashed, and /status says how many
    there are"""

    def _index_with_report(self):
        index = MinHashIndex(config)
        with open(EXAMPLE_REPORT) as fjson:
            report = SmdaReport.fromDict(json.load(fjson))
        assert report is not None
        sample_entry = index.getStorage().addSmdaReport(report)
        assert sample_entry is not None
        index.updateMinHashesForSample(sample_entry.sample_id, force_recalculation=True)
        return index, sample_entry

    def _hashed_function_ids(self, index, sample_id):
        return sorted(f.function_id for f in index.getStorage().getFunctionsBySampleId(sample_id) if f.minhash)

    def test_hashing_records_the_running_smda_and_a_repair_is_a_no_op(self):
        index, sample_entry = self._index_with_report()
        storage = index.getStorage()
        self.assertGreater(len(self._hashed_function_ids(index, sample_entry.sample_id)), 0)
        self.assertEqual([], storage.getSamplesWithStaleMinHashes(Worker.getMinHashCompatibilityThreshold()))
        self.assertEqual(0, index.getStatus(with_pichash=False)["status"]["num_samples_with_stale_minhashes"])
        report = index.getResultForJob(index.repairMinHashes(force_recalculation=True))
        self.assertEqual(0, report["num_samples_stale"])
        self.assertEqual(0, report["num_samples_repaired"])

    def test_a_stale_sample_is_rehashed_in_place(self):
        index, sample_entry = self._index_with_report()
        storage = index.getStorage()
        hashed_before = self._hashed_function_ids(index, sample_entry.sample_id)
        bands_before = {band: dict(hashes) for band, hashes in storage._bands.items()}
        storage.setMinHashVersionForSamples("4.0.0", [sample_entry.sample_id])
        self.assertEqual([sample_entry.sample_id], storage.getSamplesWithStaleMinHashes("4.4.5"))
        self.assertEqual(1, index.getStatus(with_pichash=False)["status"]["num_samples_with_stale_minhashes"])
        report = index.getResultForJob(index.repairMinHashes(force_recalculation=True))
        self.assertEqual(1, report["num_samples_repaired"])
        self.assertEqual(len(hashed_before), report["num_functions_dropped"])
        self.assertEqual(len(hashed_before), report["num_functions_rehashed"])
        self.assertEqual(SmdaConfig().VERSION, report["smda_version"])
        self.assertEqual(hashed_before, self._hashed_function_ids(index, sample_entry.sample_id))
        # the same escaper gives the same band index back, without a rebuild
        self.assertEqual(bands_before, {band: dict(hashes) for band, hashes in storage._bands.items()})
        self.assertEqual([], storage.getSamplesWithStaleMinHashes("4.4.5"))
        self.assertEqual(0, index.getStatus(with_pichash=False)["status"]["num_samples_with_stale_minhashes"])

    def test_a_sample_whose_disassembly_is_gone_keeps_its_minhashes(self):
        """hash first, drop second: without disassembly nothing could replace the old hashes"""
        index, sample_entry = self._index_with_report()
        storage = index.getStorage()
        hashed_before = self._hashed_function_ids(index, sample_entry.sample_id)
        storage.setMinHashVersionForSamples("4.0.0", [sample_entry.sample_id])
        storage.deleteXcfgForSampleId(sample_entry.sample_id)
        report = index.getResultForJob(index.repairMinHashes(force_recalculation=True))
        self.assertEqual(1, report["num_samples_stale"])
        self.assertEqual(1, report["num_samples_skipped"])
        self.assertEqual(0, report["num_samples_repaired"])
        self.assertEqual(0, report["num_functions_dropped"])
        self.assertEqual(hashed_before, self._hashed_function_ids(index, sample_entry.sample_id))
        # still stale: the next smda with disassembly at hand can repair it
        self.assertEqual([sample_entry.sample_id], storage.getSamplesWithStaleMinHashes("4.4.5"))

    def test_a_sample_without_a_recorded_version_counts_as_stale(self):
        index, sample_entry = self._index_with_report()
        storage = index.getStorage()
        storage._minhash_versions.clear()
        self.assertEqual([sample_entry.sample_id], storage.getSamplesWithStaleMinHashes("4.4.5"))
        storage.setMinHashVersionForSamples("garbage", [sample_entry.sample_id])
        self.assertEqual([sample_entry.sample_id], storage.getSamplesWithStaleMinHashes("4.4.5"))

    def test_the_full_recalculation_records_the_version_for_every_sample(self):
        index, sample_entry = self._index_with_report()
        storage = index.getStorage()
        storage._minhash_versions.clear()
        index.getResultForJob(index.recalculateMinHashes(force_recalculation=True))
        self.assertEqual([], storage.getSamplesWithStaleMinHashes("4.4.5"))


class RepairRouteAndClient(unittest.TestCase):
    def test_the_route_schedules_the_job(self):
        index = MagicMock()
        index.repairMinHashes.return_value = "0123456789abcdef01234567"
        resp = falcon.Response()
        StatusResource(index).on_post_repair_minhashes(falcon.Request(falcon.testing.create_environ(path="/repair_minhashes", method="POST")), resp)
        assert resp.data is not None
        self.assertEqual("0123456789abcdef01234567", json.loads(resp.data)["data"])
        index.repairMinHashes.assert_called_once_with(force_recalculation=True)

    def test_the_client_posts_and_answers_the_job_id(self):
        response = MagicMock(status_code=200)
        response.json.return_value = {"status": "successful", "data": "0123456789abcdef01234567"}
        with patch("mcrit.client.McritClient.requests.post", return_value=response) as post:
            self.assertEqual("0123456789abcdef01234567", McritClient("http://mcrit.test").repairMinHashes())
        self.assertIn("/repair_minhashes", post.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
