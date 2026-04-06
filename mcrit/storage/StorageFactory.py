from mcrit.storage.MemoryStorage import MemoryStorage
from mcrit.storage.MongoDbStorage import MongoDbStorage


class StorageFactory:

    STORAGE_METHOD_MEMORY = "memory"
    STORAGE_METHOD_MONGODB = "mongodb"

    @staticmethod
    def getStorage(mcrit_config):
        if mcrit_config.STORAGE_CONFIG.STORAGE_METHOD == StorageFactory.STORAGE_METHOD_MONGODB:
            return MongoDbStorage(mcrit_config)
        return MemoryStorage(mcrit_config)
