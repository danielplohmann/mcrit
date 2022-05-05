# from mcrit.storage.alchemy.AlchemyStorage import AlchemyStorage
from mcrit.storage.MemoryStorage import MemoryStorage
from mcrit.storage.MongoDbStorage import MongoDbStorage


class StorageFactory:

    STORAGE_METHOD_MEMORY = "memory"
    STORAGE_METHOD_ALCHEMY = "alchemy"
    STORAGE_METHOD_MONGODB = "mongodb"

    @staticmethod
    def getStorage(storage_config):
        if storage_config.STORAGE_METHOD == StorageFactory.STORAGE_METHOD_MONGODB:
            return MongoDbStorage(storage_config)
        # Alchemy not supported right now
        # if storage_config.STORAGE_METHOD == StorageFactory.STORAGE_METHOD_ALCHEMY:
        #     return AlchemyStorage(storage_config)
        return MemoryStorage(storage_config)
