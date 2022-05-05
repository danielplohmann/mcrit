class MatchingCache(object):
    """A reduced in-memory view for a selection of FunctionEntry and corresponding SampleEntry objects - implements a subset of StorageInterface"""

    def __init__(self, cache_data):
        self._func_id_to_minhash = cache_data["func_id_to_minhash"]
        self._func_id_to_sample_id = cache_data["func_id_to_sample_id"]

    def getMinHashByFunctionId(self, function_id):
        return self._func_id_to_minhash[function_id]

    def getSampleIdByFunctionId(self, function_id):
        return self._func_id_to_sample_id[function_id]
