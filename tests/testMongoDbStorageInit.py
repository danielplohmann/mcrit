import logging
import threading
import time
from unittest import TestCase, main

import pytest

import mcrit.storage.MongoDbStorage as mongo_db_storage_module
from mcrit.config.McritConfig import McritConfig
from mcrit.config.MinHashConfig import MinHashConfig
from mcrit.config.QueueConfig import QueueConfig
from mcrit.config.ShinglerConfig import ShinglerConfig
from mcrit.config.StorageConfig import StorageConfig
from mcrit.storage.MongoDbStorage import MongoDbStorage
from mcrit.storage.StorageFactory import StorageFactory

from .context import getTestMongoServerAndPort

LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")
logging.disable(logging.CRITICAL)


def buildMcritConfig():
    server, port = getTestMongoServerAndPort()
    storage_config = StorageConfig(
        STORAGE_METHOD=StorageFactory.STORAGE_METHOD_MONGODB,
        STORAGE_SERVER=server,
        STORAGE_PORT=port,
        STORAGE_MONGODB_DBNAME="test_mongodbstorage_init_mcrit",
        STORAGE_DROP_DISASSEMBLY=False,
    )
    mcrit_config = McritConfig()
    mcrit_config.STORAGE_CONFIG = storage_config
    mcrit_config.MINHASH_CONFIG = MinHashConfig()
    mcrit_config.MINHASH_CONFIG.MINHASH_SIGNATURE_LENGTH = 10
    mcrit_config.MINHASH_CONFIG.MINHASH_SIGNATURE_BITS = 8
    mcrit_config.SHINGLER_CONFIG = ShinglerConfig()
    mcrit_config.QUEUE_CONFIG = QueueConfig()
    return mcrit_config


@pytest.mark.mongo
class MongoDbStorageInitTest(TestCase):
    """The server shares one MongoDbStorage across all request threads, so the lazy
    initialisation in _getDb() must construct exactly one MongoClient no matter how
    many threads arrive cold at the same time (#109)."""

    def setUp(self):
        self.config = buildMcritConfig()
        self.storage = MongoDbStorage(self.config)

    def tearDown(self):
        if self.storage._database is not None:
            db_name = self.config.STORAGE_CONFIG.STORAGE_MONGODB_DBNAME
            self.storage._database.client.drop_database(db_name)

    def testConcurrentColdGetDbCreatesExactlyOneClient(self):
        num_threads = 8
        construction_count = [0]
        count_lock = threading.Lock()
        real_mongo_client = mongo_db_storage_module.MongoClient

        def countingMongoClient(*args, **kwargs):
            with count_lock:
                construction_count[0] += 1
            # hold the check-to-assign window open, so that without synchronisation in
            # _getDb() every cold thread would reliably construct its own client
            time.sleep(0.1)
            return real_mongo_client(*args, **kwargs)

        barrier = threading.Barrier(num_threads)
        databases = [None] * num_threads
        errors = []

        def hitGetDb(slot):
            try:
                barrier.wait()
                databases[slot] = self.storage._getDb()
            except Exception as exc:
                errors.append(exc)

        setattr(mongo_db_storage_module, "MongoClient", countingMongoClient)
        try:
            threads = [threading.Thread(target=hitGetDb, args=(slot,)) for slot in range(num_threads)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
        finally:
            setattr(mongo_db_storage_module, "MongoClient", real_mongo_client)

        self.assertEqual([], errors)
        self.assertEqual(1, construction_count[0])
        for database in databases:
            self.assertIs(databases[0], database)

    def testEnsureIndexAndUnknownFamilyIsIdempotent(self):
        database = self.storage._getDb()
        db_name = self.config.STORAGE_CONFIG.STORAGE_MONGODB_DBNAME
        database.client.drop_database(db_name)
        # bootstrapping twice (as the server and worker processes do against a shared
        # database) must yield exactly one family "" with family_id 0
        self.storage._ensureIndexAndUnknownFamily()
        self.storage._ensureIndexAndUnknownFamily()
        second_storage = MongoDbStorage(self.config)
        second_storage._getDb()
        self.assertEqual(1, database.families.count_documents({"family_id": 0}))
        self.assertEqual(1, database.families.count_documents({"family_name": ""}))
        unknown_family = self.storage.getFamily(0)
        assert unknown_family is not None
        self.assertEqual("", unknown_family.family_name)
        # the families counter must be past 0, so the next family can never collide with id 0
        self.assertEqual(1, self.storage.addFamily("another_family"))


if __name__ == "__main__":
    main()
