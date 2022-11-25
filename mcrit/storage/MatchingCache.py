class MatchingCache(object):
    """A reduced in-memory view for a selection of FunctionEntry and corresponding SampleEntry objects - implements a subset of StorageInterface"""

    def __init__(self, cache_data):
        self._func_id_to_minhash = cache_data["func_id_to_minhash"]
        self._func_id_to_sample_id = cache_data["func_id_to_sample_id"]
        self._sample_id_to_func_ids = cache_data["sample_id_to_func_ids"]

    def isSampleId(self, sample_id):
        return sample_id in self._sample_id_to_func_ids

    def getMinHashByFunctionId(self, function_id):
        return self._func_id_to_minhash[function_id]

    def getSampleIdByFunctionId(self, function_id):
        return self._func_id_to_sample_id[function_id]

    def getFunctionIdsBySampleId(self, sample_id):
        return self._sample_id_to_func_ids[sample_id]

    def addFunctionEntriesToCache(self, function_entries):
        for function_entry in function_entries:
            self._func_id_to_minhash[function_entry.function_id] = function_entry.minhash
            self._func_id_to_sample_id[function_entry.function_id] = function_entry.sample_id
            sample_id = function_entry.sample_id
            if sample_id not in self._sample_id_to_func_ids:
                self._sample_id_to_func_ids[sample_id] = []
            self._sample_id_to_func_ids[sample_id].append(function_entry.function_id)
