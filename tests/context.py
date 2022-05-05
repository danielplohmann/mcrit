# -*- coding: utf-8 -*-

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import mcrit
from mcrit.config.McritConfig import McritConfig

config = McritConfig()

from mcrit.queue.QueueFactory import QueueFactory
from mcrit.storage.StorageFactory import StorageFactory

config.STORAGE_CONFIG.STORAGE_METHOD = StorageFactory.STORAGE_METHOD_MEMORY
config.QUEUE_CONFIG.QUEUE_METHOD = QueueFactory.QUEUE_METHOD_FAKE
