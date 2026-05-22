class MatchingCache:
    """A reduced in-memory view for a selection of FunctionEntry and corresponding SampleEntry objects - implements a subset of StorageInterface"""

    def __init__(self, cache_data):
        self._func_id_to_minhash = cache_data["func_id_to_minhash"]
        self._func_id_to_sample_id = cache_data["func_id_to_sample_id"]
        self._sample_id_to_func_ids = cache_data["sample_id_to_func_ids"]

    def _setFunctionEntry(self, function_id, sample_id, minhash):
        if function_id in self._func_id_to_sample_id:
            old_sample_id = self._func_id_to_sample_id[function_id]
            if old_sample_id in self._sample_id_to_func_ids:
                self._sample_id_to_func_ids[old_sample_id].discard(function_id)
                if not self._sample_id_to_func_ids[old_sample_id]:
                    del self._sample_id_to_func_ids[old_sample_id]
        self._func_id_to_minhash[function_id] = minhash
        self._func_id_to_sample_id[function_id] = sample_id
        if sample_id not in self._sample_id_to_func_ids:
            self._sample_id_to_func_ids[sample_id] = set()
        self._sample_id_to_func_ids[sample_id].add(function_id)

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
            self._setFunctionEntry(function_entry.function_id, function_entry.sample_id, function_entry.minhash)


class StorageBackedMatchingCache(MatchingCache):
    """A matching cache that reuses storage-backed data without mutating the underlying storage."""

    def __init__(self, storage, function_ids):
        self._storage = storage
        self._func_id_to_minhash = {}
        unique_function_ids = set(function_ids)
        self._func_id_to_sample_id = dict(self._storage.getSampleIdsByFunctionIds(list(unique_function_ids)))
        self._sample_id_to_func_ids = {}
        missing_function_ids = unique_function_ids.difference(self._func_id_to_sample_id)
        if missing_function_ids:
            raise KeyError(missing_function_ids.pop())
        for function_id, sample_id in self._func_id_to_sample_id.items():
            if sample_id not in self._sample_id_to_func_ids:
                self._sample_id_to_func_ids[sample_id] = set()
            self._sample_id_to_func_ids[sample_id].add(function_id)

    def getMinHashByFunctionId(self, function_id):
        if function_id in self._func_id_to_minhash:
            return self._func_id_to_minhash[function_id]
        if function_id not in self._func_id_to_sample_id:
            raise KeyError(function_id)
        return self._storage.getMinHashByFunctionId(function_id)
