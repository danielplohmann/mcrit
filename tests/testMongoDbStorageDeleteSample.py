from types import MethodType, SimpleNamespace
from unittest import TestCase

from mcrit.config.McritConfig import McritConfig
from mcrit.config.MinHashConfig import MinHashConfig
from mcrit.config.StorageConfig import StorageConfig
from mcrit.storage.MongoDbStorage import MongoDbStorage


class FakeCollection:
    def __init__(self, documents=None):
        self.documents = list(documents or [])
        self.find_calls = []
        self.delete_many_calls = []
        self.delete_one_calls = []

    def find(self, query, projection):
        self.find_calls.append((query, projection))
        return list(self.documents)

    def delete_many(self, query):
        self.delete_many_calls.append(query)

    def delete_one(self, query):
        self.delete_one_calls.append(query)


class FakeDb(dict):
    def __getattr__(self, name):
        return self[name]


class MongoDbStorageDeleteSampleTest(TestCase):
    def setUp(self):
        config = McritConfig()
        config.STORAGE_CONFIG = StorageConfig()
        config.MINHASH_CONFIG = MinHashConfig()
        config.MINHASH_CONFIG.MINHASH_SIGNATURE_BITS = 32
        config.MINHASH_CONFIG.MINHASH_SIGNATURE_LENGTH = 10
        self.storage = MongoDbStorage(config)

    def testDeleteSampleUsesProjectedFunctionFields(self):
        functions = FakeCollection(
            [
                {"function_id": 10, "minhash": bytes(range(40)).hex()},
                {"function_id": 11, "minhash": bytes(range(40, 80)).hex()},
            ]
        )
        samples = FakeCollection()
        families = FakeCollection()
        self.storage._database = FakeDb(
            functions=functions, samples=samples, families=families
        )
        self.storage.getSampleById = MethodType(
            lambda _self, sample_id: SimpleNamespace(
                family_id=1,
                statistics={"num_functions": 2},
                is_library=False,
            ),
            self.storage,
        )
        self.storage.isSampleId = MethodType(
            lambda _self, sample_id: sample_id == 7, self.storage
        )
        band_updates = []
        family_updates = []
        self.storage._updateBands = MethodType(
            lambda _self, band_hashes, method="push": band_updates.append(
                (band_hashes, method)
            ),
            self.storage,
        )
        self.storage._updateFamilyStats = MethodType(
            lambda _self, family_id, num_samples, num_functions, num_library_samples: (
                family_updates.append(
                    (family_id, num_samples, num_functions, num_library_samples)
                )
            ),
            self.storage,
        )
        self.storage.getFamily = MethodType(
            lambda _self, family_id: SimpleNamespace(
                num_samples=1, family_id=family_id
            ),
            self.storage,
        )
        self.storage._updateDbState = MethodType(lambda _self: None, self.storage)

        result = self.storage.deleteSample(7)

        self.assertTrue(result)
        self.assertEqual(
            [({"sample_id": 7}, {"_id": 0, "function_id": 1, "minhash": 1})],
            functions.find_calls,
        )
        self.assertEqual([{"sample_id": 7}], functions.delete_many_calls)
        self.assertEqual([{"sample_id": 7}], samples.delete_one_calls)
        self.assertEqual([(1, -1, -2, 0)], family_updates)
        self.assertEqual(1, len(band_updates))
        self.assertEqual("pull", band_updates[0][1])
