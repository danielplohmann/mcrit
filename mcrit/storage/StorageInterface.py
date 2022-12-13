import random
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple, Union

from mcrit.minhash.MinHash import MinHash

if TYPE_CHECKING: # pragma: no cover
    from mcrit.config.StorageConfig import StorageConfig
    from mcrit.config.McritConfig import McritConfig
    from mcrit.config.MinHashConfig import MinHashConfig
    from mcrit.storage.FunctionEntry import FunctionEntry
    from mcrit.storage.MatchingCache import MatchingCache
    from mcrit.storage.MemoryStorage import MemoryStorage
    from mcrit.storage.SampleEntry import SampleEntry
    from smda.common.SmdaFunction import SmdaFunction
    from smda.common.SmdaReport import SmdaReport

SampleId = int
FunctionId = int
FamilyId = int
PicHash = int
FamilyId = int
BandId = int
BandHash = int
PicHash = int
Sha256 = str


class StorageInterface:
    _config: "StorageConfig"
    _band_projection: None

    def __init__(self, config: "McritConfig") -> None:
        """Set the StorageConfig, sets up an empty Storage or loads existing data, ensures indexing,
        and ensures the existence of an Family with name \"\" and family_id 0.

        Args:
            config: the configuration of this Storage

        Raises:
            AssertionError: If family_id 0 already exists, but does not refer to Family \"\".
        """
        self._config = config
        self._storage_config = config.STORAGE_CONFIG
        self._minhash_config = config.MINHASH_CONFIG
        self._band_projection = None

    # -> Set[function_id]
    def getCandidatesForMinHash(self, minhash: "MinHash", band_matches_required=1) -> Set[int]:
        """Given a MinHash, return all candidates from all matching bands.

        Args:
            minhash: a MinHash
            band_matches_required: the number of bands a minhash needs to match before being considered a candidate

        Returns:
            candidates: a set of function_ids
        """
        raise NotImplementedError

    # -> Dict[function_id, Set[function_id]]
    def getCandidatesForMinHashes(self, function_id_to_minhash: Dict[int, "MinHash"], band_matches_required=1) -> Dict[int, Set[int]]:
        """Given MinHashes by function_id, return all candidates from all matching bands.

        Args:
            function_id_to_minhash: a dict mapping a function_id to a MinHash.
            band_matches_required: the number of bands a minhash needs to match before being considered a candidate

        Returns:
            candidates: a dict mapping a function_id to a set of candidate function_ids.
        """
        raise NotImplementedError

    def deleteXcfgData(self) -> None:
        """Delete XCFG data of all samples from the storage

        Returns:
            None
        """
        raise NotImplementedError

    def deleteXcfgForSampleId(self, sample_id: int) -> None:
        """Remove a sample's XCFG from the storage

        Args:
            sample_id: the sample_id whose XCFG will be deleted

        Returns:
            None
        """
        raise NotImplementedError

    def clearStorage(self) -> None:
        """Delete all contents in the storage, reinitialize an empty storage, ensure indexing and add Family \"\" with family_id.

        Returns:
            None
        """
        raise NotImplementedError

    def getSampleBySha256(self, sha256: str) -> Optional["SampleEntry"]:
        """Check if the given SHA256 is already associated with a sample in the storage

        Args:
            sha256: The SHA256 value to look up.

        Returns:
            A SampleEntry with the specified SHA256 or None, if no such SampleEntry exists.
        """
        raise NotImplementedError

    def addSmdaReport(self, smda_report: "SmdaReport", isQuery=False) -> Optional["SampleEntry"]:
        """Add a SMDA report to storage to create its sample representation and return corresponding SampleEntry object.
        This also adds the sample's functions. If the sample's family is not in storage yet, it will be added.
        If a sample with the same SHA256 already exists in storage, smda_report is not added and None is returned.

        Args:
            smda_report: the SmdaReport to add to the storage
            isQuery: True if this SmdaReport is associated with a matching query and its data shall not be persisted in the main DB

        Returns:
            A SampleEntry corresponding to smda_report or None, if SmdaReport was already added.
        """
        raise NotImplementedError

    def importSampleEntry(self, sample_entry: "SampleEntry") -> Optional["SampleEntry"]:
        """Import a sample_entry to storage based on a previously exported SampleEntry.
        We assume that the family_id was already remapped by the MinHashIndex, meaning that only the sample_id needs to be adjusted
        If a sample with the same SHA256 already exists in storage, sample_entry is not added and None is returned.

        Args:
            sample_entry: the SampleEntry to add to the storage

        Returns:
            An adjusted SampleEntry if successful or None, if SampleEntry was already added.
        """
        raise NotImplementedError

    def importFunctionEntry(self, function_entry: "FunctionEntry") -> Optional["FunctionEntry"]:
        """Import a function_entry to storage based on a previously exported FunctionEntry.
        We assume that the family_id and sample_id were already remapped by the MinHashIndex, meaning that only the function_id needs to be adjusted.

        Args:
            function_entry: the FunctionEntry to add to the storage

        Returns:
            An adjusted FunctionEntry if successful or None, if we failed somewhere in the procedure
        """
        raise NotImplementedError


    def importFunctionEntries(self, function_entries: List["FunctionEntry"]) -> Optional[List["FunctionEntry"]]:
        """Import multiple function_entries to storage based on previously exported FunctionEntry objects.
        We assume that the family_id and sample_id were already remapped by the MinHashIndex, meaning that only the function_ids need to be adjusted.

        Args:
            function_entries: List of FunctionEntry objects to add to the storage

        Returns:
            A list of adjusted FunctionEntry objects if successful or None, if we failed somewhere in the procedure
        """
        raise NotImplementedError

    def modifyFamily(self, family_id: int, update_information: dict) -> bool:
        """Update a family from the storage

        Args:
            family_id: the id of the sample to modify
            update_information: a dictionary with update information for fields (family_name, is_library)

        Returns:
            True if family_id was contained in the storage and updated successfully, False otherwise
        """
        raise NotImplementedError

    def modifySample(self, sample_id: int, update_information: dict) -> bool:
        """Update a sample from the storage

        Args:
            sample_id: the id of the sample to modify
            update_information: a dictionary with update information for fields (family_name, version, component, is_library)

        Returns:
            True if sample_id was contained in the storage and updated successfully, False otherwise
        """
        raise NotImplementedError

    def deleteSample(self, sample_id: int) -> bool:
        """Remove a sample from the storage, also removes all functions of the sample.
        All minhashes will be removed from the bands.

        Args:
            sample_id: the id of the sample to delete

        Returns:
            True if sample_id was contained in the storage and deleted successfully, False otherwise
        """
        raise NotImplementedError

    def getSampleIds(self) -> List[int]:
        """Return a list of all sample_ids.

        Returns:
            a list of all sample_ids
        """
        raise NotImplementedError

    def getSampleIdByFunctionId(self, function_id: int) -> Optional[int]:
        """For a given function_id, return the corresponding sample_id or None, if function_id was not found.

        Args:
            function_id: a function_id

        Returns:
            the corresponding sample_id or None, if function_id was not found
        """
        raise NotImplementedError

    def getSampleById(self, sample_id: int) -> Optional["SampleEntry"]:
        """Given a sample_id, return the respective SampleEntry or None, if sample_id was not found.

        Args:
            sample_id: a sample_id

        Returns:
            the respective SampleEntry or None, if sample_id was not found
        """
        raise NotImplementedError

    def getSamplesByFamilyId(self, family_id: int) -> Optional[List["SampleEntry"]]:
        """Return all SampleEntries for a given family_id.

        Args:
            family_id: a family_id

        Returns:
            a list of all SampleEntries belonging to the given family_id.
            For a nonexistant family_id None is returned.
        """
        raise NotImplementedError

    def getSamples(self, start_index: int, limit: int) -> Optional["SampleEntry"]:
        """Iterate the sample collection and provide a slice (regardless of sample_id), 
        covering up to <limit> items, starting from start_index

        Args:
            start_index: <n>th sample in the collection
            limit: number of entries to return at most

        Returns:
            the respective SampleEntries

        """
        raise NotImplementedError

    def getLibraryInfoForSampleId(self, sample_id: int) -> Optional[Dict[str, str]]:
        """Return family_name and version of sample if it is a library or None otherwise

        Args:
            sample_id: a sample id

        Returns:
            If sample_id exists in storage and belongs to a library: a dict with keys
                "family" and "version" containing the respective data from the sample_id's SampeEnty, otherwise None.
        """
        raise NotImplementedError

    def getFunctionsBySampleId(self, sample_id: int) -> Optional[List["FunctionEntry"]]:
        """For a given sample_id, get all corresponding FunctionEntries.

        Args:
            sample_id: a sample_id

        Returns:
            A list of FunctionEntries or None, if sample_id does not exist
        """
        raise NotImplementedError

    def getFunctionIdsBySampleId(self, sample_id: int) -> Optional[List["int"]]:
        """For a given sample_id, get all corresponding function_ids.

        Args:
            sample_id: a sample_id

        Returns:
            A list of int or None, if sample_id does not exist
        """
        raise NotImplementedError

    def getFunctionById(self, function_id: int, with_xcfg=False) -> Optional["FunctionEntry"]:
        """Given a function_id, return the respective FunctionEntry or None, if function_id is not contained otherwise.

        Args:
            function_id: a function id
            with_xcfg: include xcfg info (default: False)

        Returns:
            the respective FunctionEntry or None, if function_id is not contained otherwise

        """
        raise NotImplementedError

    def getFunctions(self, start_index: int, limit: int) -> Optional["FunctionEntry"]:
        """Iterate the function collection and provide a slice (regardless of function_id), 
        covering up to <limit> items, starting from start_index

        Args:
            start_index: <n> function in the collection
            limit: number of entries to return at most

        Returns:
            the respective FunctionEntries

        """
        raise NotImplementedError

    # TODO remove this?
    def clearMatchingCache(self) -> None:
        """Clears the temporary matching cache

        Returns:
            None
        """
        raise NotImplementedError

    # TODO: make a MatchingCacheInterface, or MemoryStorage a subclass of MatchingCache?
    # TODO rename -> get?
    def createMatchingCache(self, function_ids: List[int]) -> Union["MemoryStorage", "MatchingCache"]:
        """Creates a temporary matching cache, for a list of function_ids

        Args:
            function_ids: list of function ids

        Returns:
            a matching cache for the specified list of function ids
        """
        raise NotImplementedError

    def isSampleId(self, sample_id: int) -> bool:
        """Check if a sample with sample_id exists in storage.

        Args:
            sample_id the sample id to check

        Returns:
            True if the sample_id exists, False otherwise
        """
        raise NotImplementedError

    def isFunctionId(self, function_id: int) -> bool:
        """Check if a function with function_id exists in storage.

        Args:
            function_id the function id to check

        Returns:
            True if the function_id exists, False otherwise
        """
        raise NotImplementedError

    def isFamilyId(self, family_id: int) -> bool:
        """Check if a family with family_id exists in storage.

        Args:
            family_id the family id to check

        Returns:
            True if the family_id exists, False otherwise
        """
        raise NotImplementedError

    def isPicHash(self, pichash: int) -> bool:
        """Check if a given PicHash exists in storage.

        Args:
            pichash: the pichash to check

        Returns:
            True if the PicHash exists, False otherwise
        """
        raise NotImplementedError

    # TODO check if a minhash can ever not have a function id
    def addMinHash(self, minhash: "MinHash") -> bool:
        """Add a MinHash object to the respective functions in storage.

        Args:
            minhash: the minhash to add

        Returns:
            True if the the respective function exists, and the MinHash could be added,
                False otherwise
        """
        raise NotImplementedError

    def addMinHashes(self, minhashes: List["MinHash"]) -> None:
        """Add multiple MinHash objects at once. MinHashes, that cannot be added
        (e.g. because of missing function ids) will be ignored.

        Args:
            minhashes: the list of MinHash objects to add

        Returns:
            None
        """
        raise NotImplementedError

    # TODO dict of what?
    def getContent(self, sample_ids: Optional[List[int]] = None) -> Dict[str, Any]:
        # filter sample_ids erlauben
        raise NotImplementedError

    # TODO dict of what?
    def addContent(self, content: Dict[str, Any]) -> None:
        # remaps ids, filters sha256
        raise NotImplementedError

    # TODO dict of what?
    def setContent(self, content: Dict[str, Any]) -> None:
        raise NotImplementedError

    def addFamily(self, family_name: str) -> int:
        """Add family, if not already known and return family_id

        Args:
            family_name: The name of the family to add

        Returns:
            family_id of the added (or already existing) family name
        """
        raise NotImplementedError

    def deleteFamily(self, family_id: int, keep_samples: Optional[str] = False) -> bool:
        """Delete family if known and return boolean success state

        Args:
            family_id: The family_id of the family to delete
            keep_samples: instead of deleting all samples and functions, reassign their family to "Unnamed (0)"

        Returns:
            True if successful
        """
        raise NotImplementedError

    def getFamilyIds(self) -> List[int]:
        """Returns a List of all family ids

        Returns:
            a List of all family ids
        """
        raise NotImplementedError

    def getFamilyId(self, family_name: str) -> Optional[int]:
        """Return family if known, None otherwise

        Args:
            family_name: Name of the family to look up

        Returns:
            family id corresponding to family_name or None
        """
        raise NotImplementedError

    def getFamily(self, family_id: int) -> Optional[str]:
        """Get the Family Name corresponding to a family id. Returns None, if family_id is not in storage.

        Args:
            family_id: the id of the family to look up

        Returns:
            the name of the family or None

        """
        raise NotImplementedError

    # TODO find out if it is really possible that a Function Object has no MinHash.
    def getMinHashByFunctionId(self, function_id: int) -> Optional[bytes]:
        """Get the MinHash's bytes of a function, if the function exists and has a MinHash object.

        Args:
            function_id: the id of the function

        Returns:
            The function's MinHash's bytes, or None

        """
        raise NotImplementedError

    # TODO can this happen, that the Function has no pichash?
    # TODO Maybe remove this function, or restore original behavior?
    # -> Dict[pichash, Set[Tuple[sample_id, function_id]]]
    def getPicHashMatchesByFunctionId(self, function_id: int) -> Optional[Dict[int, Set[Tuple[int, int]]]]:
        """Get the PicHash for a given function_id and also return all other sample_id/function_id pairs having the same PicHash

        Args:
            function_id: the function id for PicHash matching

        Returns:
            None if the function_id does not exist, or does not have a pichash. Otherwise a dict containing the functions pichash as key and the following value: a set of (sample_id, function_id) having the given pichash
        """
        raise NotImplementedError

    def getPicHashMatchesByFunctionIds(self, function_ids: List[int]) -> Dict[int, Set[Tuple[int, int]]]:
        """Get the PicHashes for given function_ids and also return all other sample_id/function_id pairs having the same PicHashes
        Nonexisting function ids or functions without pichashes will be ignored.

        Args:
            function_ids: the function ids for PicHash matching

        Returns:
            a dict mapping the function's pichashes to a set of (sample_id, function_id) having the same pichash.
        """
        raise NotImplementedError

    def getPicHashMatchesBySampleId(self, sample_id: int) -> Optional[Dict[int, Set[Tuple[int, int]]]]:
        """Get the PicHashes for a given sample_id's function_ids and also return all other sample_id/function_id pairs having the same PicHashes.
        Functions without pichashes will be ignored.
        If sample_id is not in storage, None will be returned

        Args:
            sample_id: the sample id for PicHash matching

        Returns:
            a dict mapping the sample's function's pichashes to a set of (sample_id, function_id) having the same pichash or None.
        """
        raise NotImplementedError

    def getMatchesForPicHash(self, pichash: int) -> Set[Tuple[int, int, int]]:
        """Get the set of all (family_id, sample_id, function_id) tuples for a given PicHash. If no function has the given pichash, the empty set is returned

        Args:
            pichash: the pichash to look up

        Returns:
            a set of (family_id, sample_id, function_id) tuples with the given pichash
        """
        raise NotImplementedError


    def getMatchesForPicBlockHash(self, picblockhash: int) -> Set[Tuple[int, int, int, int]]:
        """Get the set of all (family_id, sample_id, function_id, offset) tuples for a given PicBlockHash. If no function has the given picblockhash, the empty set is returned

        Args:
            picblockhash: the picblockhash to look up

        Returns:
            a set of (family_id, sample_id, function_id, offset) tuples with the given picblockhash
        """
        raise NotImplementedError

    def getStats(self) -> Dict[str, Union[int, Dict[int, int]]]:
        raise NotImplementedError

    def getUnhashedFunctions(self, function_ids: Optional[List[int]] = None, only_function_ids=False) -> List["FunctionEntry"]:
        """Given a list of function_ids, return all FunctionEntry objects corresponding to these IDs if they do not have a minhash yet.
        Otherwise, return all FunctionEntry objects that do not have a minhash.

        Args:
            function_ids: (optional) a list of function_ids
            only_function_ids: (optional) instead if FunctionEntry objects, only return function_ids

        Returns:
            a list of FunctionEntry objects without minhash
        """
        raise NotImplementedError


    def getUniqueBlocks(self, sample_ids: Optional[List[int]] = None, progress_reporter=None) -> Dict:
        """Given a list of sample_ids, return all basic blocks that are only found in any of these samples (and no other samples in the storage)

        Args:
            sample_ids: (optional) a list of sample_ids
            progress_reporter: (optional) might be passed by worker to inquiry progress of this DB only operation

        Returns:
            a dictionary with the isolated blocks
        """
        raise NotImplementedError

    def findFamilyByString(self, needle: str, max_num_results: int = 100) -> Dict[int, str]:
        """Given a needle, return all families that contain the term we are searching.

        Args:
            needle: a search string
            max_num_results: (optional) maximum number of results to return, default 100

        Returns:
            a dictionary of family_id->famile_name containing the needle
        """
        raise NotImplementedError

    def findSampleByString(self, needle: str, max_num_results: int = 100) -> Dict[int, "SampleEntry"]:
        """Given a needle, return all SampleEntry objects that contain the term we are searching.

        Args:
            needle: a search string
            max_num_results: (optional) maximum number of results to return, default 100

        Returns:
            a list of sample_id->SampleEntry containing the needle
        """
        raise NotImplementedError

    def findFunctionByString(self, needle: str, max_num_results: int = 100) -> Dict[int, "FunctionEntry"]:
        """Given a needle, return all FunctionEntry objects that contain the term we are searching.

        Args:
            needle: a search string
            max_num_results: (optional) maximum number of results to return, default 100

        Returns:
            a dict of function_id->FunctionEntry containing the needle
        """
        raise NotImplementedError

    def createBandhashProjection(self, minhash):
        """Calculate a projection for index permutation based on a given minhash
        Args:
            minhash: the MinHash used as reference
        Returns:
            a dict containing signature indices used for bandhashing by band id
        """
        band_projection = {}
        random.seed(self._storage_config.STORAGE_BAND_SEED)
        band_index = 0
        for band_size, num_bands in self._storage_config.STORAGE_BANDS.items():
            for _ in range(num_bands):
                index_sequence = [index for index in range(len(minhash.getMinHashInt()))]
                random.shuffle(index_sequence)
                band_projection[band_index] = index_sequence[:band_size]
                band_index += 1
        return band_projection

    # -> Dict[BandIndex, BandHash]
    def getBandHashesForMinHash(self, minhash: "MinHash") -> Dict[int, int]:
        """Calculate band hashes for a given minhash, based on config parameters (STORAGE_BAND_SEED, STORAGE_BANDS)
        Args:
            minhash: the MinHash for which the BandHashes will be calculated
        Returns:
            a dict containing BandHashes by BandId
        """
        if self._band_projection is None:
            self._band_projection = self.createBandhashProjection(minhash)
        band_hashes = {}
        minhash_data = minhash.getMinHashInt()
        for band_index, permutation in self._band_projection.items():
            band_data = [minhash_data[i] for i in permutation]
            hashed_band_data = MinHash.hashData(band_data, 0)
            band_hashes[band_index] = hashed_band_data
        return band_hashes
