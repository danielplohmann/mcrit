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
