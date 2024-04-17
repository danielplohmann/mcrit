import logging
from dataclasses import asdict, dataclass, field

from mcrit.config.ConfigInterface import ConfigInterface, default_field
from mcrit.queue.QueueFactory import QueueFactory


@dataclass
class QueueConfig(ConfigInterface):
    # QUEUE_METHOD:... = QueueFactory.QUEUE_METHOD_FAKE
    QUEUE_METHOD: ... = QueueFactory.QUEUE_METHOD_MONGODB
    QUEUE_SERVER: str = "127.0.0.1"
    QUEUE_PORT: str = "27017"
    # By default, MongoDbStorage's DB's name and MongoQueue's DB's name are both "mcrit"
    # Changing one DB name here or at runtime DOES NOT change the other name!
    QUEUE_MONGODB_DBNAME: str = "mcrit"
    QUEUE_MONGODB_USERNAME: str = None
    QUEUE_MONGODB_PASSWORD: str = None
    QUEUE_MONGODB_FLAGS: str = ""
    QUEUE_MONGODB_COLLECTION_NAME: str = "queue"
    QUEUE_TIMEOUT: int = 300
    QUEUE_MAX_ATTEMPTS: int = 3
    # QUEUE_CLEAN_INTERVAL is the time EACH WORKER waits between cleaning
    QUEUE_CLEAN_INTERVAL: int = 20 * 60  # Clean every 20 minutes
    # timeout in seconds for child processes spawned by SpawningWorker
    QUEUE_SPAWNINGWORKER_CHILDREN_TIMEOUT: int = 60 * 60
