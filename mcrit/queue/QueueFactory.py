from pymongo import MongoClient


class QueueFactory:

    QUEUE_METHOD_FAKE = "fake"
    QUEUE_METHOD_MONGODB = "mongodb"

    @staticmethod
    def getQueue(config, storage=None, consumer_id=None):
        queue_config = config.QUEUE_CONFIG
        if queue_config.QUEUE_METHOD == QueueFactory.QUEUE_METHOD_FAKE:
            from mcrit.queue.LocalQueue import LocalQueue
            from mcrit.Worker import Worker

            if storage is None:
                raise ValueError("QueueFactory needs storage to set up LocalQueue")
            queue = LocalQueue()
            queue.set_worker(Worker(queue=queue, storage=storage, config=config))
        else:
            from mcrit.libs.mongoqueue import MongoQueue

            if consumer_id is None:
                raise ValueError("QueueFactory needs consumer_id to set up MongoQueue")
            db = MongoClient(host=queue_config.QUEUE_SERVER, port=queue_config.QUEUE_PORT)
            collection = db[queue_config.QUEUE_MONGODB_DBNAME].queue
            queue = MongoQueue(
                collection,
                consumer_id,
                timeout=queue_config.QUEUE_TIMEOUT,
                max_attempts=queue_config.QUEUE_MAX_ATTEMPTS,
            )
        queue.clean_interval = queue_config.QUEUE_CLEAN_INTERVAL
        return queue
