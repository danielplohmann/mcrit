import datetime
import functools
import logging
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

import requests
from smda.common.SmdaReport import SmdaReport
from smda.Disassembler import Disassembler

from mcrit.queue.LocalQueue import Job
from mcrit.storage.FamilyEntry import FamilyEntry
from mcrit.storage.FunctionEntry import FunctionEntry
from mcrit.storage.SampleEntry import SampleEntry

# Only do basicConfig if no handlers have been configured
if not logging.root.handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")
LOGGER = logging.getLogger(__name__)


class JobTerminatedError(Exception):
    """Raised by awaitResult when the awaited job was terminated instead of finishing."""


def isJobTerminated(job):
    if job is None:
        return True

    return job.is_terminated


def isJobFailed(job):
    return (job is not None) and (job.is_failed)


def isJobFinishedTerminatedOrFailed(job):
    return isJobTerminated(job) or (job.result is not None) or isJobFailed(job)


def handle_response(response) -> Any:
    data = None
    if response.status_code in [500, 501]:
        LOGGER.warning("McritClient received status code 500 from MCRIT.")
    elif response.status_code in [400, 404, 410]:
        # nothing to here as of now
        pass
    elif response.status_code in [200, 202]:
        json_response = response.json()
        if "status" in json_response and json_response["status"] == "successful":
            data = json_response["data"]
    return data


class McritClient:
    """Python client for the MCRIT REST API.

    Every public method maps to one endpoint (see docs/api_reference.md) and answers the
    parsed ``data`` of the server's JSON response, converted to the storage entry classes
    where one exists; ``None`` when the server answered with a failure status. The return
    annotations describe this default mode; with ``raw_responses=True`` every method answers
    the ``requests.Response`` itself instead. Methods that
    schedule work on the MCRIT queue answer the job id, which ``getResultForJob`` or
    ``awaitResult`` turn into the result.

    Args:
        mcrit_server: base URL of the server, default ``http://localhost:8000``
        apitoken: sent as the ``apitoken`` header when the server requires one
        username: sent as the ``username`` header and recorded with the jobs this client creates
        raw_responses: when True every method returns the ``requests.Response`` unchanged
    """

    def __init__(self, mcrit_server: Optional[str] = None, apitoken: Optional[str] = None, username: Optional[str] = None, raw_responses: bool = False) -> None:
        self.mcrit_server = "http://localhost:8000"
        self.headers = {}
        self.raw = True if raw_responses else False
        if apitoken:
            self.headers.update({"apitoken": apitoken})
        if username:
            self.headers.update({"username": username})
        if mcrit_server is not None:
            self.mcrit_server = mcrit_server

    @staticmethod
    def _passthrough(response: requests.Response) -> Any:
        # raw_responses mode: the Response itself, whatever the method's annotation says
        return response

    def setApitoken(self, apitoken: str) -> None:
        """Send ``apitoken`` as the ``apitoken`` header from now on."""
        self.headers.update({"apitoken": apitoken})

    def setUsername(self, username: str) -> None:
        """Send ``username`` as the ``username`` header from now on; MCRIT records it with the jobs this client creates."""
        self.headers.update({"username": username})

    def _getMatchingRequestParams(
        self, minhash_threshold=None, pichash_size=None, force_recalculation=None, band_matches_required=None, exclude_self_matches=False, sample_group_only=False
    ):
        params = {}
        if minhash_threshold is not None:
            params["minhash_score"] = minhash_threshold
        if pichash_size is not None:
            params["pichash_size"] = pichash_size
        if force_recalculation is not None:
            params["force_recalculation"] = force_recalculation
        if band_matches_required is not None:
            params["band_matches_required"] = band_matches_required
        if exclude_self_matches:
            params["exclude_self_matches"] = True
        if sample_group_only:
            params["sample_group_only"] = True
        return params

    def respawn(self) -> Optional[Dict[str, Any]]:
        """POST /respawn: drop the whole database and set up a fresh, empty instance. Answers the server's confirmation message."""
        response = requests.post(f"{self.mcrit_server}/respawn", headers=self.headers)
        return handle_response(response)

    def completeMinhashes(self) -> Optional[str]:
        """GET /complete_minhashes: schedule a job that calculates every missing minhash. Answers the job id."""
        response = requests.get(f"{self.mcrit_server}/complete_minhashes", headers=self.headers)
        if self.raw:
            return self._passthrough(response)
        return handle_response(response)

    def rebuildIndex(self) -> Optional[str]:
        """GET /rebuild_index: schedule a job that drops the band index and rebuilds it from the stored minhashes. Answers the job id."""
        response = requests.get(f"{self.mcrit_server}/rebuild_index", headers=self.headers)
        if self.raw:
            return self._passthrough(response)
        return handle_response(response)

    def recalculatePicHashes(self) -> Optional[str]:
        """GET /recalculate_pichashes: schedule a job that recalculates the pichashes of samples hashed with an older smda. Answers the job id."""
        response = requests.get(f"{self.mcrit_server}/recalculate_pichashes", headers=self.headers)
        if self.raw:
            return self._passthrough(response)
        return handle_response(response)

    def recalculateMinHashes(self) -> Optional[str]:
        """GET /recalculate_minhashes: schedule a job that drops every minhash and recalculates all of them. Answers the job id."""
        response = requests.get(f"{self.mcrit_server}/recalculate_minhashes", headers=self.headers)
        if self.raw:
            return self._passthrough(response)
        return handle_response(response)

    def addReport(self, smda_report: SmdaReport) -> Optional[Tuple[SampleEntry, Optional[str]]]:
        """POST /samples: submit a disassembled SMDA report as a new sample.

        Returns:
            the SampleEntry and the id of the minhashing job (None when the sample already existed or
            no hashing was scheduled); None when the server rejected the report
        """
        smda_json = smda_report.toDict()
        response = requests.post(f"{self.mcrit_server}/samples", json=smda_json, headers=self.headers)
        if self.raw:
            return self._passthrough(response)
        data = handle_response(response)
        if data is not None:
            if "job_id" in data:
                job_id = data["job_id"]
            else:
                job_id = None
            return SampleEntry.fromDict(data["sample_info"]), job_id

    def addBinarySample(
        self,
        binary: bytes,
        filename: Optional[str] = None,
        family: Optional[str] = None,
        version: Optional[str] = None,
        is_dump: bool = False,
        base_addr: Optional[int] = None,
        bitness: Optional[int] = None,
    ) -> Optional[str]:
        """POST /samples/binary: submit a raw binary for disassembly and insertion.

        Args:
            binary: file content, or a memory dump when ``is_dump`` is set
            filename, family, version: metadata stored with the sample
            is_dump: disassemble as a mapped image loaded at ``base_addr``
            base_addr: image base of a dump
            bitness: 32 or 64, for dumps

        Returns:
            the id of the disassembly job; its result carries the sample entry
        """
        query_fields = []
        if filename is not None:
            query_fields.append(f"filename={filename}")
        if family is not None:
            query_fields.append(f"family={family}")
        if version is not None:
            query_fields.append(f"version={version}")
        if is_dump:
            query_fields.append("is_dump=1")
        if base_addr is not None:
            query_fields.append(f"base_addr=0x{base_addr:x}")
        if bitness is not None and bitness in [32, 64]:
            query_fields.append(f"bitness={bitness}")
        query_string = ""
        if len(query_fields) > 0:
            query_string = "?" + "&".join(query_fields)
        response = requests.post(f"{self.mcrit_server}/samples/binary{query_string}", data=binary, headers=self.headers)
        return handle_response(response)

    ###########################################
    ### Families
    ###########################################

    def modifyFamily(self, family_id: int, family_name: Optional[str] = None, is_library: Optional[bool] = None) -> Optional[Dict[str, Any]]:
        """PUT /families/{family_id}: rename a family and/or mark it as a library. Answers the confirmation message, None when rejected."""
        update_dict = {}
        if family_name is not None:
            update_dict["family_name"] = family_name
        if is_library is not None:
            update_dict["is_library"] = is_library
        response = requests.put(f"{self.mcrit_server}/families/{family_id}", update_dict, headers=self.headers)
        return handle_response(response)

    def getFamily(self, family_id: int, with_samples: bool = True) -> Optional[FamilyEntry]:
        """GET /families/{family_id}: one family, with its samples unless ``with_samples`` is False. None for an unknown id."""
        query_params = "?with_samples=true" if with_samples else "?with_samples=false"
        response = requests.get(f"{self.mcrit_server}/families/{family_id}{query_params}", headers=self.headers)
        if self.raw:
            return self._passthrough(response)
        data = handle_response(response)
        if data is not None:
            return FamilyEntry.fromDict(data)
        return None

    def getFamilies(self) -> Optional[Dict[int, FamilyEntry]]:
        """GET /families: every family, keyed by family id."""
        response = requests.get(f"{self.mcrit_server}/families", headers=self.headers)
        if self.raw:
            return self._passthrough(response)
        data = handle_response(response)
        if data is not None:
            return {i: FamilyEntry.fromDict(entry) for i, entry in data.items()}
        return None

    def isFamilyId(self, family_id: int) -> bool:
        """GET /families/{family_id}: whether the id names a family."""
        response = requests.get(f"{self.mcrit_server}/families/{family_id}", headers=self.headers)
        if self.raw:
            return self._passthrough(response)
        data = handle_response(response)
        if data is not None:
            return True
        return False

    def deleteFamily(self, family_id: int, keep_samples: bool = False) -> Optional[bool]:
        """DELETE /families/{family_id}: delete a family and its samples, or with ``keep_samples`` move the samples to the unknown family. Answers True on success, None for an unknown id."""
        query_params = "?keep_samples=true" if keep_samples else "?keep_samples=false"
        response = requests.delete(f"{self.mcrit_server}/families/{family_id}{query_params}", headers=self.headers)
        return handle_response(response)

    ###########################################
    ### Samples
    ###########################################

    def isSampleId(self, sample_id: int) -> bool:
        """GET /samples/{sample_id}: whether the id names a sample."""
        response = requests.get(f"{self.mcrit_server}/samples/{sample_id}", headers=self.headers)
        if self.raw:
            return self._passthrough(response)
        data = handle_response(response)
        if data is not None:
            return True
        return False

    def modifySample(
        self, sample_id: int, family_name: Optional[str] = None, version: Optional[str] = None, component: Optional[str] = None, is_library: Optional[bool] = None
    ) -> Optional[Dict[str, Any]]:
        """PUT /samples/{sample_id}: change a sample's family, version, component and/or library flag. Answers the confirmation message, None when rejected."""
        update_dict = {}
        if family_name is not None:
            update_dict["family_name"] = family_name
        if version is not None:
            update_dict["version"] = version
        if component is not None:
            update_dict["component"] = component
        if is_library is not None:
            update_dict["is_library"] = is_library
        response = requests.put(f"{self.mcrit_server}/samples/{sample_id}", update_dict, headers=self.headers)
        return handle_response(response)

    def deleteSample(self, sample_id: int) -> Optional[bool]:
        """DELETE /samples/{sample_id}: delete a sample with its functions and index entries. Answers True on success."""
        response = requests.delete(f"{self.mcrit_server}/samples/{sample_id}", headers=self.headers)
        return handle_response(response)

    def getSamplesByFamilyId(self, family_id: int) -> Optional[Dict[int, SampleEntry]]:
        """The samples of a family keyed by sample id (via GET /families/{family_id}); None for an unknown family."""
        family_data = self.getFamily(family_id)
        if family_data is not None:
            return family_data.samples
        return None

    def getSampleById(self, sample_id: int) -> Optional[SampleEntry]:
        """GET /samples/{sample_id}: one sample; None for an unknown id."""
        response = requests.get(f"{self.mcrit_server}/samples/{sample_id}", headers=self.headers)
        if self.raw:
            return self._passthrough(response)
        data = handle_response(response)
        if data is not None:
            return SampleEntry.fromDict(data)

    def getSamples(self, start: int = 0, limit: int = 0) -> Optional[Dict[int, SampleEntry]]:
        """GET /samples: samples keyed by id, from sample id ``start`` on and at most ``limit`` many (0 = all)."""
        query_string = ""
        if (isinstance(start, int) and start >= 0) and (isinstance(limit, int) and limit >= 0):
            query_string = f"?start={start}&limit={limit}"
        response = requests.get(f"{self.mcrit_server}/samples{query_string}", headers=self.headers)
        if self.raw:
            return self._passthrough(response)
        data = handle_response(response)
        if data is not None:
            return {int(k): SampleEntry.fromDict(v) for k, v in data.items()}

    ###########################################
    ### Functions
    ###########################################

    def getFunctionsBySampleId(self, sample_id: int) -> Optional[List[FunctionEntry]]:
        """GET /samples/{sample_id}/functions: every function of a sample; None for an unknown id."""
        response = requests.get(f"{self.mcrit_server}/samples/{sample_id}/functions", headers=self.headers)
        if self.raw:
            return self._passthrough(response)
        data = handle_response(response)
        if data is not None:
            return [FunctionEntry.fromDict(function_entry_dict) for function_entry_dict in data.values()]

    def getFunctions(self, start: int = 0, limit: int = 0) -> Optional[Dict[int, FunctionEntry]]:
        """GET /functions: functions keyed by id, from function id ``start`` on and at most ``limit`` many (0 = all)."""
        query_string = ""
        if (isinstance(start, int) and start >= 0) and (isinstance(limit, int) and limit >= 0):
            query_string = f"?start={start}&limit={limit}"
        response = requests.get(f"{self.mcrit_server}/functions{query_string}", headers=self.headers)
        if self.raw:
            return self._passthrough(response)
        data = handle_response(response)
        if data is not None:
            return {int(k): FunctionEntry.fromDict(v) for k, v in data.items()}

    def getFunctionsByIds(self, function_ids: List[int], with_label_only: bool = False) -> Dict[int, FunctionEntry]:
        """POST /functions: the functions with the given ids keyed by id; with ``with_label_only`` only those carrying a label."""
        query_with_label_only = "?with_label_only=True" if with_label_only else ""
        function_id_string = ",".join(["%d" % fid for fid in function_ids])
        response = requests.post(f"{self.mcrit_server}/functions{query_with_label_only}", data=function_id_string, headers=self.headers)
        if self.raw:
            return self._passthrough(response)
        data = handle_response(response)
        if data is not None:
            return {int(k): FunctionEntry.fromDict(v) for k, v in data.items()}
        return {}

    def isFunctionId(self, function_id: int) -> bool:
        """GET /functions/{function_id}: whether the id names a function."""
        response = requests.get(f"{self.mcrit_server}/functions/{function_id}", headers=self.headers)
        if self.raw:
            return self._passthrough(response)
        data = handle_response(response)
        if self.raw:
            return data
        if data is not None:
            return True
        return False

    def getFunctionById(self, function_id: int, with_xcfg: bool = False) -> Optional[FunctionEntry]:
        """GET /functions/{function_id}: one function, with its disassembly when ``with_xcfg`` is set; None for an unknown id."""
        query_with_xcfg = "?with_xcfg=True" if with_xcfg else ""
        response = requests.get(f"{self.mcrit_server}/functions/{function_id}{query_with_xcfg}", headers=self.headers)
        data = handle_response(response)
        if self.raw:
            return self._passthrough(response)
        if data is not None:
            return FunctionEntry.fromDict(data)

    ###########################################
    ### Matching
    ###########################################

    def requestMatchesForSmdaReport(
        self,
        smda_report: SmdaReport,
        minhash_threshold: Optional[int] = None,
        pichash_size: Optional[int] = None,
        band_matches_required: Optional[int] = None,
        force_recalculation: bool = False,
    ) -> Optional[str]:
        """POST /query: schedule matching of an SMDA report that is not stored in MCRIT against the corpus.

        Args:
            minhash_threshold: minimum minhash score (0-100) for a function match
            pichash_size: pichash size to match with
            band_matches_required: bands that must agree before minhashes are compared
            force_recalculation: ignore a cached result of the same request

        Returns:
            the job id; the result is a MatchingResult dict
        """
        smda_json = smda_report.toDict()
        params = self._getMatchingRequestParams(minhash_threshold, pichash_size, force_recalculation, band_matches_required)
        response = requests.post(f"{self.mcrit_server}/query", json=smda_json, headers=self.headers, params=params)
        if self.raw:
            return self._passthrough(response)
        return handle_response(response)

    def requestMatchesForMappedBinary(
        self,
        binary: bytes,
        base_address: int,
        minhash_threshold: Optional[int] = None,
        pichash_size: Optional[int] = None,
        band_matches_required: Optional[int] = None,
        disassemble_locally: bool = True,
        force_recalculation: bool = False,
    ) -> Optional[str]:
        """Match a memory dump mapped at ``base_address`` against the corpus: disassembled with the local smda and sent to POST /query, or with ``disassemble_locally=False`` sent to POST /query/binary/mapped/{base_address} for the server to disassemble. Matching parameters as for requestMatchesForSmdaReport. Answers the job id, None when local disassembly failed."""
        if disassemble_locally:
            disassembler = Disassembler()
            smda_report = disassembler.disassembleBuffer(binary, base_address)
            if smda_report.status == "error":
                return None
            return self.requestMatchesForSmdaReport(
                smda_report,
                minhash_threshold=minhash_threshold,
                pichash_size=pichash_size,
                band_matches_required=band_matches_required,
                force_recalculation=force_recalculation,
            )

        params = self._getMatchingRequestParams(minhash_threshold, pichash_size, force_recalculation, band_matches_required)
        response = requests.post(f"{self.mcrit_server}/query/binary/mapped/{base_address}", binary, headers=self.headers, params=params)
        if self.raw:
            return self._passthrough(response)
        return handle_response(response)

    def requestMatchesForUnmappedBinary(
        self,
        binary: bytes,
        minhash_threshold: Optional[int] = None,
        pichash_size: Optional[int] = None,
        band_matches_required: Optional[int] = None,
        disassemble_locally: bool = True,
        force_recalculation: bool = False,
    ) -> Optional[str]:
        """Match a file against the corpus: disassembled with the local smda and sent to POST /query, or with ``disassemble_locally=False`` sent to POST /query/binary for the server to disassemble. Matching parameters as for requestMatchesForSmdaReport. Answers the job id, None when local disassembly failed."""
        if disassemble_locally:
            disassembler = Disassembler()
            smda_report = disassembler.disassembleUnmappedBuffer(binary)
            if smda_report.status == "error":
                return None
            return self.requestMatchesForSmdaReport(
                smda_report,
                minhash_threshold=minhash_threshold,
                pichash_size=pichash_size,
                band_matches_required=band_matches_required,
                force_recalculation=force_recalculation,
            )

        params = self._getMatchingRequestParams(minhash_threshold, pichash_size, force_recalculation, band_matches_required)

        response = requests.post(f"{self.mcrit_server}/query/binary", binary, headers=self.headers, params=params)
        if self.raw:
            return self._passthrough(response)
        return handle_response(response)

    def requestMatchesForSample(
        self,
        sample_id: int,
        minhash_threshold: Optional[int] = None,
        pichash_size: Optional[int] = None,
        band_matches_required: Optional[int] = None,
        force_recalculation: bool = False,
    ) -> Optional[str]:
        """GET /matches/sample/{sample_id}: schedule matching of a stored sample against the corpus; matching parameters as for requestMatchesForSmdaReport. Answers the job id."""
        params = self._getMatchingRequestParams(minhash_threshold, pichash_size, force_recalculation, band_matches_required)
        response = requests.get(f"{self.mcrit_server}/matches/sample/{sample_id}", headers=self.headers, params=params)
        if self.raw:
            return self._passthrough(response)
        return handle_response(response)

    def requestMatchesForSampleVs(
        self,
        sample_id: int,
        other_sample_id: int,
        minhash_threshold: Optional[int] = None,
        pichash_size: Optional[int] = None,
        band_matches_required: Optional[int] = None,
        force_recalculation: bool = False,
    ) -> Optional[str]:
        """GET /matches/sample/{sample_id}/{other_sample_id}: schedule matching of one stored sample against another; matching parameters as for requestMatchesForSmdaReport. Answers the job id."""
        params = self._getMatchingRequestParams(minhash_threshold, pichash_size, force_recalculation, band_matches_required)
        response = requests.get(f"{self.mcrit_server}/matches/sample/{sample_id}/{other_sample_id}", headers=self.headers, params=params)
        if self.raw:
            return self._passthrough(response)
        return handle_response(response)

    def requestMatchesCross(
        self,
        sample_ids: List[int],
        sample_group_only: bool = False,
        minhash_threshold: Optional[int] = None,
        pichash_size: Optional[int] = None,
        band_matches_required: Optional[int] = None,
        force_recalculation: bool = False,
    ) -> Optional[str]:
        """GET /matches/sample/cross/{sample_ids}: schedule cross matching of the samples against each other (``sample_group_only``) or against the corpus; matching parameters as for requestMatchesForSmdaReport. Answers the id of the job combining the per-sample results."""
        params = self._getMatchingRequestParams(minhash_threshold, pichash_size, force_recalculation, band_matches_required, sample_group_only=sample_group_only)
        response = requests.get(f"{self.mcrit_server}/matches/sample/cross/{','.join([str(id) for id in sample_ids])}", headers=self.headers, params=params)
        if self.raw:
            return self._passthrough(response)
        return handle_response(response)

    def getMatchFunctionVs(self, function_id_a: int, function_id_b: int) -> Optional[Dict[str, Any]]:
        """GET /matches/function/{function_id_a}/{function_id_b}: compare two stored functions directly (minhash score, pichash equality, the matched function entry). None for an unknown id."""
        response = requests.get(f"{self.mcrit_server}/matches/function/{function_id_a}/{function_id_b}", headers=self.headers)
        if self.raw:
            return self._passthrough(response)
        return handle_response(response)

    def getMatchesForSmdaFunction(
        self,
        smda_report: SmdaReport,
        minhash_threshold: Optional[int] = None,
        pichash_size: Optional[int] = None,
        force_recalculation: Optional[bool] = None,
        band_matches_required: Optional[int] = None,
        exclude_self_matches: bool = False,
    ) -> Optional[Dict[str, Any]]:
        """POST /query/function: match an SMDA report holding a single function synchronously; ``exclude_self_matches`` drops matches with the same sample. Answers the MatchingResult dict."""
        # TODO add the same parameter possibilities that are used for regular full matching jobs
        params = self._getMatchingRequestParams(minhash_threshold, pichash_size, force_recalculation, band_matches_required, exclude_self_matches)
        response = requests.post(f"{self.mcrit_server}/query/function", json=smda_report.toDict(), headers=self.headers, params=params)
        if self.raw:
            return self._passthrough(response)
        return handle_response(response)

    def getMatchesForPicHash(self, pichash: int, summary: bool = False) -> Optional[Any]:
        """GET /query/pichash/{pichash}[/summary]: the (family_id, sample_id, function_id) tuples of the functions with this pichash, or with ``summary`` the counts of families, samples and functions."""
        summary_string = "/summary" if summary else ""
        response = requests.get(f"{self.mcrit_server}/query/pichash/{pichash:016x}{summary_string}", headers=self.headers)
        if self.raw:
            return self._passthrough(response)
        return handle_response(response)

    def getMatchesForPicBlockHash(self, picblockhash: int, summary: bool = False) -> Optional[Any]:
        """GET /query/picblockhash/{picblockhash}[/summary]: the (family_id, sample_id, function_id, offset) tuples of the basic blocks with this picblockhash, or with ``summary`` the counts of families, samples and functions."""
        summary_string = "/summary" if summary else ""
        response = requests.get(f"{self.mcrit_server}/query/picblockhash/{picblockhash:016x}{summary_string}", headers=self.headers)
        if self.raw:
            return self._passthrough(response)
        return handle_response(response)

    def getSampleBySha256(self, sample_sha256: str) -> Optional[SampleEntry]:
        """GET /samples/sha256/{sha256}: one sample by its sha256; None when unknown or malformed."""
        response = requests.get(f"{self.mcrit_server}/samples/sha256/{sample_sha256}", headers=self.headers)
        if self.raw:
            return self._passthrough(response)
        data = handle_response(response)
        if data is None:
            return None
        return SampleEntry.fromDict(data)

    ###########################################
    ### Status, Results
    ###########################################

    def getStatus(self, with_pichash: bool = True) -> Optional[Dict[str, Any]]:
        """GET /status: statistics of the instance (database state, counts of samples, families, functions and, with ``with_pichash``, unique pichashes, smda version and escaper fingerprint)."""
        query_string = ""
        if with_pichash:
            query_string = "?with_pichash=True"
        response = requests.get(f"{self.mcrit_server}/status{query_string}", headers=self.headers)
        if self.raw:
            return self._passthrough(response)
        return handle_response(response)

    def getVersion(self) -> Optional[str]:
        """GET /version: the version of the MCRIT server."""
        response = requests.get(f"{self.mcrit_server}/version", headers=self.headers)
        if self.raw:
            return self._passthrough(response)
        data = handle_response(response)
        if isinstance(data, dict) and "version" in data:
            return data["version"]
        return None

    def getJobCount(self, filter: Optional[str] = None) -> Optional[int]:
        """GET /jobs: how many jobs the queue holds, optionally only those whose descriptor contains ``filter``."""
        query_string = ""
        if isinstance(filter, str) and filter is not None:
            if len(query_string) == 0:
                query_string = f"?filter={filter}"
            else:
                query_string += f"&filter={filter}"
        response = requests.get(f"{self.mcrit_server}/jobs{query_string}", headers=self.headers)
        if self.raw:
            return self._passthrough(response)
        data = handle_response(response)
        if data is not None:
            return len(data)

    def getQueueStatistics(self, with_refresh: bool = False) -> Optional[Dict[str, Any]]:
        """GET /jobs/stats: queue statistics per method and state; ``with_refresh`` recounts instead of answering the cached numbers."""
        query_string = ""
        if with_refresh:
            if len(query_string) == 0:
                query_string = "?with_refresh=True"
        response = requests.get(f"{self.mcrit_server}/jobs/stats/{query_string}", headers=self.headers)
        if self.raw:
            return self._passthrough(response)
        return handle_response(response)

    def getQueueData(
        self, start: int = 0, limit: int = 0, method: Optional[str] = None, filter: Optional[str] = None, state: Optional[str] = None, ascending: bool = False
    ) -> Optional[List[Job]]:
        """GET /jobs: the queued jobs, newest first unless ``ascending``, from index ``start`` on and at most ``limit`` many (0 = all); ``method`` (job method name), ``state`` and ``filter`` (substring of the descriptor) narrow them down."""
        query_string = "?ascending=True" if ascending else ""
        if isinstance(start, int) and start > 0:
            if len(query_string) == 0:
                query_string = f"?start={start}"
            else:
                query_string += f"&start={start}"
        if isinstance(limit, int) and limit > 0:
            if len(query_string) == 0:
                query_string = f"?limit={limit}"
            else:
                query_string += f"&limit={limit}"
        if isinstance(method, str) and method is not None:
            if len(query_string) == 0:
                query_string = f"?method={method}"
            else:
                query_string += f"&method={method}"
        if isinstance(filter, str) and filter is not None:
            if len(query_string) == 0:
                query_string = f"?filter={filter}"
            else:
                query_string += f"&filter={filter}"
        if isinstance(state, str) and state is not None:
            if len(query_string) == 0:
                query_string = f"?state={state}"
            else:
                query_string += f"&state={state}"
        response = requests.get(f"{self.mcrit_server}/jobs/{query_string}", headers=self.headers)
        if self.raw:
            return self._passthrough(response)
        data = handle_response(response)
        if data is not None:
            return [Job(job_data, None) for job_data in data]

    def deleteQueueData(
        self, method: Optional[str] = None, created_before: Optional[datetime.datetime] = None, finished_before: Optional[datetime.datetime] = None
    ) -> Optional[Dict[str, int]]:
        """DELETE /jobs: delete the jobs matching all given filters. Answers ``num_deleted``."""
        query_string = ""
        if isinstance(method, str) and method is not None:
            if len(query_string) == 0:
                query_string = f"?method={method}"
            else:
                query_string += f"&method={method}"
        if isinstance(created_before, datetime.datetime) and created_before is not None:
            if len(query_string) == 0:
                query_string = f"?created_before={created_before.strftime('%Y-%m-%dT%H:%M:%S')}"
            else:
                query_string += f"&created_before={created_before.strftime('%Y-%m-%dT%H:%M:%S')}"
        if isinstance(finished_before, datetime.datetime) and finished_before is not None:
            if len(query_string) == 0:
                query_string = f"?finished_before={finished_before.strftime('%Y-%m-%dT%H:%M:%S')}"
            else:
                query_string += f"&finished_before={finished_before.strftime('%Y-%m-%dT%H:%M:%S')}"
        response = requests.delete(f"{self.mcrit_server}/jobs/{query_string}", headers=self.headers)
        if self.raw:
            return self._passthrough(response)
        return handle_response(response)

    def deleteJob(self, job_id: str) -> Optional[Dict[str, int]]:
        """DELETE /jobs/{job_id}: delete one job and its result. Answers ``num_deleted``."""
        response = requests.delete(f"{self.mcrit_server}/jobs/{job_id}", headers=self.headers)
        if self.raw:
            return self._passthrough(response)
        return handle_response(response)

    def getJobData(self, job_id: str) -> Optional[Job]:
        """GET /jobs/{job_id}: one job; None for an unknown or malformed id."""
        response = requests.get(f"{self.mcrit_server}/jobs/{job_id}", headers=self.headers)
        if self.raw:
            return self._passthrough(response)
        data = handle_response(response)
        if data is not None:
            return Job(data, None)

    def getResultForJob(self, job_id: str, compact: bool = False) -> Optional[Any]:
        """GET /jobs/{job_id}/result: the result of a job, None while it has not finished; ``compact`` strips the per-function matches of a matching result."""
        query_string = "?compact=True" if compact else ""
        response = requests.get(f"{self.mcrit_server}/jobs/{job_id}/result{query_string}", headers=self.headers)
        if self.raw:
            return self._passthrough(response)
        return handle_response(response)

    def getResult(self, result_id: str, compact: bool = False) -> Optional[Any]:
        """GET /results/{result_id}: the result stored under a result id; ``compact`` strips the per-function matches of a matching result."""
        query_string = "?compact=True" if compact else ""
        response = requests.get(f"{self.mcrit_server}/results/{result_id}{query_string}", headers=self.headers)
        if self.raw:
            return self._passthrough(response)
        return handle_response(response)

    def getJobForResult(self, result_id: str) -> Optional[Job]:
        """GET /results/{result_id}/job: the job that produced a result."""
        response = requests.get(f"{self.mcrit_server}/results/{result_id}/job", headers=self.headers)
        if self.raw:
            return self._passthrough(response)
        data = handle_response(response)
        if data is not None:
            return Job(data, None)

    def awaitResult(self, job_id: Optional[str], sleep_time: float = 2, compact: bool = False) -> Optional[Any]:
        """Poll GET /jobs/{job_id} every ``sleep_time`` seconds until the job finished, then fetch its result.

        Raises:
            JobTerminatedError: when the job was terminated instead of finishing
        """
        if job_id is None:
            return None
        job = self.getJobData(job_id)
        while not isJobFinishedTerminatedOrFailed(job):
            time.sleep(sleep_time)
            job = self.getJobData(job_id)
        if isJobTerminated(job):
            raise JobTerminatedError
        assert job is not None
        result_id = job.result
        return self.getResult(result_id, compact=compact)

    ###########################################
    ### Import / Export
    ###########################################

    def getExportData(self, sample_ids: Optional[List[int]] = None, compress_data: bool = True) -> Optional[Dict[str, Any]]:
        """GET /export or /export/{sample_ids}: the export of the whole instance or of the given samples, for addImportData on another instance; ``compress_data`` compresses the function entries per sample.

        Raises:
            ValueError: when ``sample_ids`` is not a list of int
        """
        compress_uri_param = "?compress=True" if compress_data else ""
        result_data = {}
        if sample_ids is not None:
            if isinstance(sample_ids, list) and all(isinstance(item, int) for item in sample_ids):
                sample_ids_as_str = ",".join([str(sample_id) for sample_id in sample_ids])
                response = requests.get(f"{self.mcrit_server}/export/{sample_ids_as_str}{compress_uri_param}", headers=self.headers)
                result_data = handle_response(response)
            else:
                raise ValueError("sample_ids must be a list of int.")
        else:
            response = requests.get(f"{self.mcrit_server}/export{compress_uri_param}", headers=self.headers)
            result_data = handle_response(response)
        return result_data

    def addImportData(self, import_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """POST /import: import the data getExportData produced (ids are remapped, known samples skipped). Answers the import report.

        Raises:
            ValueError: when ``import_data`` is not a dict
        """
        if not isinstance(import_data, dict):
            raise ValueError("Can only forward dictionaries with export data.")
        response = requests.post(f"{self.mcrit_server}/import", json=import_data, headers=self.headers)
        return handle_response(response)

    ###########################################
    ### Unique Blocks
    ###########################################

    @staticmethod
    def _getUniqueBlocksParams(covers_required=None, min_instructions=None):
        # covers_required is the k of the k-of-n block cover, min_instructions drops shorter blocks
        # before it is chosen; omitted parameters leave the server defaults (10 and 0) in place
        params = {}
        if covers_required is not None:
            params["covers_required"] = covers_required
        if min_instructions is not None:
            params["min_instructions"] = min_instructions
        return params

    def requestUniqueBlocksForSamples(self, sample_ids: List[int], covers_required: Optional[int] = None, min_instructions: Optional[int] = None) -> Optional[str]:
        """GET /uniqueblocks/samples/{sample_ids}: schedule the search for basic blocks unique to these samples; ``covers_required`` is the k of the k-of-n block cover, ``min_instructions`` drops shorter blocks. Answers the job id.

        Raises:
            ValueError: when ``sample_ids`` is not a list of int
        """
        if isinstance(sample_ids, list) and all(isinstance(item, int) for item in sample_ids):
            sample_ids_as_str = ",".join([str(sample_id) for sample_id in sample_ids])
            params = self._getUniqueBlocksParams(covers_required, min_instructions)
            response = requests.get(f"{self.mcrit_server}/uniqueblocks/samples/{sample_ids_as_str}", headers=self.headers, params=params)
            result_data = handle_response(response)
        else:
            raise ValueError("sample_ids must be a list of int.")
        return result_data

    def requestUniqueBlocksForFamily(self, family_id: int, covers_required: Optional[int] = None, min_instructions: Optional[int] = None) -> Optional[str]:
        """GET /uniqueblocks/family/{family_id}: schedule the search for basic blocks unique to the family's samples; parameters as for requestUniqueBlocksForSamples. Answers the job id.

        Raises:
            ValueError: when ``family_id`` is not an int
        """
        if isinstance(family_id, int):
            params = self._getUniqueBlocksParams(covers_required, min_instructions)
            response = requests.get(f"{self.mcrit_server}/uniqueblocks/family/{family_id}", headers=self.headers, params=params)
            result_data = handle_response(response)
        else:
            raise ValueError("family_id must be an int.")
        return result_data

    ###########################################
    ### Search
    ###########################################

    # When performing an initial search, the cursor should be set to None.
    # Search results are of the following form:
    # {
    #     "search_results": {
    #         id1: found_entry1,
    #         id2: found_entry2,
    #         ...
    #     },
    #     "cursor": {
    #         "forward": forward cursor,
    #         "backward": backward cursor,
    #     }
    # }
    # To get further results, perform a search using the forward cursor.
    # To get back to the previous search results, use the backward cursor.
    # If no further or previous results are available, the forward or backward cursor will be None.
    #
    # IMPORTANT: A cursor shall only be used in combination with the same
    # search_term, is_ascending and sort_by value that were used when the cursor was returned from mcrit.
    # If those parameters are altered, mcrit's behavior is undefined.

    def _search_base(self, search_kind, search_term, cursor=None, is_ascending=True, sort_by=None, limit=None):
        params = {
            "query": search_term,
            "is_ascending": is_ascending,
        }
        if cursor is not None:
            params["cursor"] = cursor
        if sort_by is not None:
            params["sort_by"] = sort_by
        if limit is not None:
            params["limit"] = limit
        encoded_params = urllib.parse.urlencode(params)
        response = requests.get(f"{self.mcrit_server}/search/{search_kind}?{encoded_params}", headers=self.headers)
        return handle_response(response)

    search_families = functools.partialmethod(_search_base, "families")

    search_samples = functools.partialmethod(_search_base, "samples")

    search_functions = functools.partialmethod(_search_base, "functions")
