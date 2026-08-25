# -*- coding: utf-8 -*-

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from mcrit.config.McritConfig import McritConfig

config = McritConfig()

from mcrit.queue.QueueFactory import QueueFactory  # noqa: E402
from mcrit.storage.StorageFactory import StorageFactory  # noqa: E402

config.STORAGE_CONFIG.STORAGE_METHOD = StorageFactory.STORAGE_METHOD_MEMORY
config.QUEUE_CONFIG.QUEUE_METHOD = QueueFactory.QUEUE_METHOD_FAKE


def getTestMongoServerAndPort():
    """Resolve TEST_MONGODB into the (server, port) pair the storage and queue configs expect.

    The variable may carry a bare host or a host:port, and the configs keep the two apart - every
    mongo-backed test resolves it through here, so pointing the suite at a non-default port works
    for all of them instead of only for the ones that remembered to split it.
    """
    mongodb_server = os.environ.get("TEST_MONGODB", "127.0.0.1")
    if ":" in mongodb_server:
        server, port = mongodb_server.rsplit(":", 1)
        return server, port
    return mongodb_server, "27017"
