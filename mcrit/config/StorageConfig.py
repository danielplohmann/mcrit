from dataclasses import asdict, dataclass, field
from typing import Dict

from mcrit.config.ConfigInterface import ConfigInterface, default_field
from mcrit.storage.StorageFactory import StorageFactory


@dataclass
class StorageConfig(ConfigInterface):
    # storage configuration, use "memory" for local testing or "alchemy" when working with larger data
    # STORAGE_METHOD = StorageFactory.STORAGE_METHOD_MEMORY
    STORAGE_METHOD: ... = StorageFactory.STORAGE_METHOD_MONGODB
    # Use this as endpoint for our server
    STORAGE_SERVER: str = "127.0.0.1"
    # By default, MongoDbStorage's DB's name and MongoQueue's DB's name are both "mcrit"
    # Changing one DB name here or at runtime DOES NOT change the other name!
    STORAGE_MONGODB_DBNAME: str = "mcrit"
    STORAGE_PORT: ... = None
    # Once MinHashes have been calculated, discard disassembly from function entries
    STORAGE_DROP_DISASSEMBLY: bool = False
    # random seed to be used when deriving sequences used as bands
    STORAGE_BAND_SEED: int = 0xDEADBEEF
    # Banding supports:
    #  * MemoryStorage: arbitrary banding configuration, multiple lengths
    #  * MongoDbStorage: arbitrary banding configuration, multiple lengths
    # configuration for bands, dict with size:number as structure - we allow mixed sizes to increase scatter effect and randomness
    _default_storage_bands = {4: 20}
    STORAGE_BANDS: Dict[int, int] = default_field(_default_storage_bands)
    # use a hashmap to cache all banding data - very memory intensive, but great speedups.
    STORAGE_CACHE: bool = False

    @property
    def STORAGE_NUM_BANDS(self):
        num_bands = 0
        if self.STORAGE_BANDS:
            num_bands = sum([value for value in self.STORAGE_BANDS.values()])
        return num_bands
