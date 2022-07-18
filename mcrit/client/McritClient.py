import time
import json
import logging
from typing import Dict, List, Optional, Tuple
from multiprocessing.sharedctypes import Value

import requests
import urllib.parse
from mcrit.storage.FunctionEntry import FunctionEntry
from mcrit.storage.SampleEntry import SampleEntry
from mcrit.queue.LocalQueue import Job
from smda.common.SmdaReport import SmdaReport
from smda.Disassembler import Disassembler


# Only do basicConfig if no handlers have been configured
if len(logging._handlerList) == 0:
    logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")
LOGGER = logging.getLogger(__name__)


class JobTerminatedError(Exception):
    pass


def isJobTerminated(job):
    if job is None:
        return True

    return job.is_terminated

def isJobFailed(job):
    return (job is not None) and (not job["attempts_left"])

def isJobFinishedTerminatedOrFailed(job):
    return isJobTerminated(job) or (job.result is not None) or isJobFailed(job)


def handle_response(response):
    data = None
    if response.status_code in [500, 501]:
        LOGGER.warn("McritClient received status code 500 from MCRIT.")
    elif response.status_code in [400, 404, 410]:
        # nothing to here as of now
        pass
    elif response.status_code in [200, 202]:
        json_response = response.json()
        if "status" in json_response and json_response["status"] == "successful":
            data = json_response["data"]
    return data


class McritClient:
    def __init__(self, mcrit_server=None):
        self.mcrit_server = "http://localhost:8000"
        if mcrit_server is not None:
            self.mcrit_server = mcrit_server

    def _getMatchingRequestParams(
        self, minhash_threshold, pichash_size, force_recalculation
    ):
        params = {}
        if minhash_threshold is not None:
            params["minhash_score"] = minhash_threshold
        if pichash_size is not None:
            params["pichash_size"] = pichash_size
        if force_recalculation is not None:
            params["force_recalculation"] = force_recalculation
        return params

    def respawn(self):
        response = requests.post(f"{self.mcrit_server}/respawn")
        return handle_response(response)

    def addReport(self, smda_report: SmdaReport) -> Tuple[SampleEntry, Optional[str]]:
        smda_json = smda_report.toDict()
        response = requests.post(f"{self.mcrit_server}/samples", json=smda_json)
        data = handle_response(response)
        if data is not None:
            if "job_id" in data:
                job_id = data["job_id"]
            else:
                job_id = None
            return SampleEntry.fromDict(data["sample_info"]), job_id

    def addBinarySample(self, binary: bytes, filename=None, family=None, version=None, is_dump=False, base_addr=None, bitness=None) -> Tuple[SampleEntry, Optional[str]]:
        query_fields = []
        if filename is not None:
            query_fields.append(f"filename={filename}")
        if family is not None:
            query_fields.append(f"family={family}")
        if version is not None:
            query_fields.append(f"version={version}")
        if is_dump:
            query_fields.append(f"is_dump=1")
        if base_addr is not None:
            query_fields.append(f"base_addr=0x{base_addr:x}")
        if bitness is not None and bitness in [32, 64]:
            query_fields.append(f"bitness={bitness}")
        query_string = ""
        if len(query_fields) > 0:
            query_string = "?" + "&".join(query_fields)
        response = requests.post(f"{self.mcrit_server}/samples/binary{query_string}", data=binary)
        return handle_response(response)

    ###########################################
    ### Families 
    ###########################################

    def getFamily(self, family_id: int, with_samples=True) -> Optional[Dict]:
        query_params = "?with_samples=true" if with_samples else "?with_samples=false"
        response = requests.get(f"{self.mcrit_server}/families/{family_id}{query_params}")
        data = handle_response(response)
        if data is not None and "samples" in data:
            data["samples"] = [
                    SampleEntry.fromDict(sample_entry_dict)
                for sample_entry_dict in sorted(data["samples"].values(), key=lambda s: s["sample_id"])
                ]
        return data 

    def getFamilies(self):
        response = requests.get(f"{self.mcrit_server}/families")
        return handle_response(response)

    def isFamilyId(self, family_id) -> bool:
        return self.getFamily(family_id, with_samples=False) is not None

    ###########################################
    ### Samples 
    ###########################################

    def isSampleId(self, sample_id):
        response = requests.get(f"{self.mcrit_server}/samples/{sample_id}")
        data = handle_response(response)
        if data is not None:
            return True
        return False

    def deleteSample(self, sample_id):
        response = requests.delete(f"{self.mcrit_server}/samples/{sample_id}")
        return handle_response(response)

    def getSamplesByFamilyId(self, family_id: int) -> Optional[List[SampleEntry]]:
        family_data = self.getFamily(family_id)
        if family_data is not None:
            return family_data["samples"]

    def getSampleById(self, sample_id):
        response = requests.get(f"{self.mcrit_server}/samples/{sample_id}")
        data = handle_response(response)
        if data is not None:
            return SampleEntry.fromDict(data)

    def getSamples(self, start=0, limit=0):
        query_string = ""
        if (isinstance(start, int) and start >= 0) and (isinstance(limit, int) and limit >= 0):
            query_string = f"?start={start}&limit={limit}"
        response = requests.get(f"{self.mcrit_server}/samples{query_string}")
        data = handle_response(response)
        if data is not None:
            return {int(k): SampleEntry.fromDict(v) for k, v in data.items()}

    ###########################################
    ### Functions
    ###########################################

    def getFunctionsBySampleId(self, sample_id):
        response = requests.get(f"{self.mcrit_server}/samples/{sample_id}/functions")
        data = handle_response(response)
        if data is not None:
            return [
                FunctionEntry.fromDict(function_entry_dict)
                for function_entry_dict in data.values()
            ]

    def getFunctions(self, start=0, limit=0):
        query_string = ""
        if (isinstance(start, int) and start >= 0) and (isinstance(limit, int) and limit >= 0):
            query_string = f"?start={start}&limit={limit}"
        response = requests.get(f"{self.mcrit_server}/functions{query_string}")
        data = handle_response(response)
        if data is not None:
            return {int(k): FunctionEntry.fromDict(v) for k, v in data.items()}

    def isFunctionId(self, function_id):
        response = requests.get(f"{self.mcrit_server}/functions/{function_id}")
        data = handle_response(response)
        if data is not None:
            return True
        return False

    def getFunctionById(self, function_id: int) -> Optional[FunctionEntry]:
        response = requests.get(f"{self.mcrit_server}/functions/{function_id}")
        data = handle_response(response)
        if data is not None:
            return FunctionEntry.fromDict(data)

    ###########################################
    ### Matching 
    ###########################################

    def requestMatchesForSmdaReport(
        self,
        smda_report: SmdaReport,
        minhash_threshold=None,
        pichash_size=None,
        force_recalculation=False,
    ) -> str:
        smda_json = smda_report.toDict()
        params = self._getMatchingRequestParams(minhash_threshold, pichash_size, force_recalculation)
        response = requests.post(f"{self.mcrit_server}/query", json=smda_json, params=params)
        return handle_response(response)

    def requestMatchesForMappedBinary(
        self,
        binary: bytes,
        base_address: int,
        minhash_threshold=None,
        pichash_size=None,
        disassemble_locally=True,
        force_recalculation=False,
    ) -> str:
        if disassemble_locally:
            disassembler = Disassembler()
            smda_report = disassembler.disassembleBuffer(binary, base_address)
            if smda_report.status == "error":
                return None
            return self.requestMatchesForSmdaReport(
                smda_report,
                minhash_threshold=minhash_threshold,
                pichash_size=pichash_size,
                force_recalculation=force_recalculation,
            )

        params = self._getMatchingRequestParams(minhash_threshold, pichash_size, force_recalculation)
        response = requests.post(f"{self.mcrit_server}/query/binary/mapped/{base_address}", binary, params=params)
        return handle_response(response)

    def requestMatchesForUnmappedBinary(
        self,
        binary: bytes,
        minhash_threshold=None,
        pichash_size=None,
        disassemble_locally=True,
        force_recalculation=False,
    ) -> str:
        if disassemble_locally:
            disassembler = Disassembler()
            smda_report = disassembler.disassembleUnmappedBuffer(binary)
            if smda_report.status == "error":
                return None
            return self.requestMatchesForSmdaReport(
                smda_report,
                minhash_threshold=minhash_threshold,
                pichash_size=pichash_size,
                force_recalculation=force_recalculation,
            )

        params = self._getMatchingRequestParams(minhash_threshold, pichash_size, force_recalculation)

        response = requests.post(f"{self.mcrit_server}/query/binary", binary, params=params)
        return handle_response(response)

    def requestMatchesForSample(
        self,
        sample_id,
        minhash_threshold=None,
        pichash_size=None,
        force_recalculation=False,
    ) -> None:
        params = self._getMatchingRequestParams(
            minhash_threshold, pichash_size, force_recalculation
        )
        response = requests.get(f"{self.mcrit_server}/matches/sample/{sample_id}", params=params)
        return handle_response(response)

    def requestMatchesForSampleVs(
        self,
        sample_id,
        other_sample_id,
        minhash_threshold=None,
        pichash_size=None,
        force_recalculation=False,
    ) -> str:
        params = self._getMatchingRequestParams(
            minhash_threshold, pichash_size, force_recalculation
        )
        response = requests.get(f"{self.mcrit_server}/matches/sample/{sample_id}/{other_sample_id}",params=params)
        return handle_response(response)

    ###########################################
    ### Status, Results 
    ###########################################

    def getStatus(self):
        response = requests.get(f"{self.mcrit_server}/status")
        return handle_response(response)

    def getJobCount(self, filter=None):
        query_string = ""
        if isinstance(filter, str) and filter is not None:
            if len(query_string) == 0:
                query_string = f"?filter={filter}"
            else:
                query_string += f"&filter={filter}"
        response = requests.get(f"{self.mcrit_server}/jobs/{query_string}")
        data = handle_response(response)
        if data is not None:
            return len(data)

    def getQueueData(self, start=0, limit=0, filter=None):
        query_string = ""
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
        if isinstance(filter, str) and filter is not None:
            if len(query_string) == 0:
                query_string = f"?filter={filter}"
            else:
                query_string += f"&filter={filter}"
        response = requests.get(f"{self.mcrit_server}/jobs/{query_string}")
        data = handle_response(response)
        if data is not None:
            return [Job(job_data, None) for job_data in data]

    def getJobData(self, job_id):
        response = requests.get(f"{self.mcrit_server}/jobs/{job_id}")
        data = handle_response(response)
        if data is not None:
            return Job(data, None)

    def getResultForJob(self, job_id):
        response = requests.get(f"{self.mcrit_server}/jobs/{job_id}/result")
        return handle_response(response)

    def getResult(self, result_id):
        response = requests.get(f"{self.mcrit_server}/results/{result_id}")
        return handle_response(response)

    def awaitResult(self, job_id, sleep_time=2):
        if job_id is None:
            return None
        job = self.getJobData(job_id)
        while not isJobFinishedTerminatedOrFailed(job):
            time.sleep(sleep_time)
            job = self.getJobData(job_id)
        if isJobTerminated(job):
            raise JobTerminatedError
        result_id = job.result
        return self.getResult(result_id)

    ###########################################
    ### Import / Export
    ###########################################

    def getExportData(self, sample_ids=None, compress_data=True) -> dict:
        compress_uri_param = "?compress=True" if compress_data else ""
        result_data = {}
        if sample_ids is not None:
            if isinstance(sample_ids, list) and all(isinstance(item, int) for item in sample_ids):
                sample_ids_as_str = ",".join([str(sample_id) for sample_id in sample_ids])
                response = requests.get(f"{self.mcrit_server}/export/{sample_ids_as_str}{compress_uri_param}")
                result_data = handle_response(response)
            else:
                raise ValueError("sample_ids must be a list of int.")
        else:
            response = requests.get(f"{self.mcrit_server}/export{compress_uri_param}")
            result_data = handle_response(response)
        return result_data

    def addImportData(self, import_data):
        if not isinstance(import_data, dict):
            raise ValueError("Can only forward dictionaries with export data.")
        response = requests.post(f"{self.mcrit_server}/import", json=import_data)
        return handle_response(response)

    ###########################################
    ### Search
    ###########################################

    def _search_base(self, search_kind, search_term):
        response = requests.get(f"{self.mcrit_server}/search/{search_kind}?query={urllib.parse.quote(search_term)}")
        return handle_response(response)

    def search_families(self, search_term):
        return self._search_base("families", search_term)

    def search_samples(self, search_term):
        return self._search_base("samples", search_term)

    def search_functions(self, search_term):
        return self._search_base("functions", search_term)

    def search_pichashes(self, search_term):
        return self._search_base("pichashes", search_term)