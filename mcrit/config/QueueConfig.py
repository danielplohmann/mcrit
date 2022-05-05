import logging
from dataclasses import asdict, dataclass, field

from mcrit.config.ConfigInterface import ConfigInterface, default_field
from mcrit.queue.QueueFactory import QueueFactory


@dataclass
class QueueConfig(ConfigInterface):
    # QUEUE_METHOD:... = QueueFactory.QUEUE_METHOD_FAKE
    QUEUE_METHOD: ... = QueueFactory.QUEUE_METHOD_MONGODB
    QUEUE_SERVER: str = "localhost"
    # By default, MongoDbStorage's DB's name and MongoQueue's DB's name are both "mcrit"
    # Changing one DB name here or at runtime DOES NOT change the other name!
    QUEUE_MONGODB_DBNAME: str = "mcrit"
    QUEUE_PORT: ... = None
    QUEUE_TIMEOUT: int = 300
    QUEUE_MAX_ATTEMPTS: int = 3
    # QUEUE_CLEAN_INTERVAL is the time EACH WORKER waits between cleaning
    QUEUE_CLEAN_INTERVAL: int = 20 * 60  # Clean every 20 minutes
