import json
import math
import os
import logging


# Only do basicConfig if no handlers have been configured
if len(logging._handlerList) == 0:
    logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")
LOGGER = logging.getLogger(__name__)


class LogBucket(object):
    """
    LogBuckets are the vehicle we use to allow fuzzy matching among discrete values.
    Using ranges of values yields at least partial matches for values near each other.
    The step size is derived as 2**floor(log2(value) / 2)

    Example ranges:

        0 [-2, -1, 0, 1, 2]
        1 [-1, 0, 1, 2, 3]
        2 [0, 1, 2, 3, 4]
        3 [1, 2, 3, 4, 6]
        4 [2, 3, 4, 6, 8]
        5 [2, 3, 4, 6, 8]
        ...
        89 [72, 80, 88, 96, 104]
        ...
        97 [80, 88, 96, 104, 112]
        ...

    When matching ranges for values 3 and 5 we get:
        3 [1, 2, 3, 4, 6]
        5 [2, 3, 4, 6, 8]
        intersection = [2, 3, 4, 6]
        union = [1, 2, 3, 4, 6, 8]
        jaccard-similarity = 4/6 = 0.66
    When matching ranges for values 89 and 97 we get:
        89 [72, 80, 88, 96, 104]
        97 [80, 88, 96, 104, 112]
        intersection = [80, 88, 96, 104]
        union = [72, 80, 88, 96, 104, 112]
        jaccard-similarity = 4/6 = 0.66
    As a result, with increasing values, buckets become wider and allow for a "scaled" amount of Fuzziness.
    """

    _value_to_bucket_range = {}

    def __init__(self, max_value=100000, bucket_width=1):
        self._max_value = max_value
        self._bucket_width = bucket_width
        self._init_buckets()

    def _init_buckets(self):
        this_path = str(os.path.abspath(__file__))
        root_path = os.sep.join(this_path.split(os.sep)[:-3])
        bucket_path = os.sep.join([root_path, "mcrit", "cache", "logbuckets.json"])
        value_to_bucket_range = {}
        if os.path.isfile(bucket_path):
            with open(bucket_path, "r") as fjson:
                value_to_bucket_range = json.load(fjson)
            self._value_to_bucket_range = {int(bucket): value for bucket, value in value_to_bucket_range.items()}
            return
        else:
            LOGGER.info(f"Calculating logbuckets for the first time - we will cache them for future use @{bucket_path}")
        value_to_bucket_id = {}
        buckets = []
        # first generate a list of logarithmically-scaled buckets and map to their values of origin
        for value in range(self._max_value * 2):
            log_value = math.log(value, 2) if value > 0 else 0
            floored_exponent = math.floor(log_value)
            if floored_exponent < 2:
                middle_bucket = value
            else:
                window_size = 2 ** math.floor(floored_exponent / 2)
                middle_bucket = window_size * math.ceil(value / window_size)
            if middle_bucket not in buckets:
                buckets.append(middle_bucket)
            value_to_bucket_id[value] = len(buckets) - 1
        # as these would have incremental steps at values that are divisible by 2, we center around best fitting buckets per value.
        for value in range(self._max_value):
            bucket_id = value_to_bucket_id[value]
            # int can be arbitrarily large in Python, "inf" is guaranteed to be bigger. :)
            best_fit = float("inf")
            best_id = bucket_id
            for test_id in [bucket_id - 1, bucket_id, bucket_id + 1]:
                if test_id < 0 or test_id >= len(buckets):
                    continue
                test_value = buckets[test_id]
                if test_value and abs(value - test_value) < best_fit:
                    best_fit = abs(value - test_value)
                    best_id = test_id
                value_to_bucket_id[value] = best_id
        # having fitted the value->middle_bucket mapping, we expand the middle values to bucket ranges
        for value in range(self._max_value):
            bucket_id = value_to_bucket_id[value]
            bucket_range = buckets[bucket_id - self._bucket_width : bucket_id + self._bucket_width + 1]
            if value < self._bucket_width:
                bucket_range = []
                for bucket_value in range(-1 * self._bucket_width + value, 0, 1):
                    bucket_range.append(bucket_value)
                for index in range(0, self._bucket_width + value + 1, 1):
                    bucket_range.append(buckets[index])
            if len(bucket_range):
                value_to_bucket_range[value] = bucket_range
        self._value_to_bucket_range = value_to_bucket_range
        with open(bucket_path, "w") as fjson:
            json.dump(value_to_bucket_range, fjson)

    def getLogBucketRange(self, value, increased_center=False):
        return self._value_to_bucket_range[value]


if __name__ == "__main__":
    log_buckets = LogBucket(16, 2)
    for value in range(16):
        bucket_range = log_buckets.getLogBucketRange(value)
        print(value, bucket_range)
