import time
import json
from typing import List, Optional, Tuple
from multiprocessing.sharedctypes import Value

import requests
from mcrit.storage.FunctionEntry import FunctionEntry
from mcrit.storage.SampleEntry import SampleEntry
from mcrit.queue.LocalQueue import Job
from smda.common.SmdaReport import SmdaReport
from smda.Disassembler import Disassembler


class JobTerminatedError(Exception):
    pass


def isJobTerminated(job):
    if job is None:
        return True

    return job.is_terminated


def isJobFinishedOrTerminated(job):
    return isJobTerminated(job) or (job.result is not None)


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
        requests.post(f"{self.mcrit_server}/respawn")

    def addReport(self, smda_report: SmdaReport) -> Tuple[SampleEntry, Optional[str]]:
        smda_json = smda_report.toDict()
        response = requests.post(f"{self.mcrit_server}/samples", json=smda_json)
        # assert response.ok
        data = response.json()["data"]
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
        if response.status_code == 400:
            return None
        job_id = response.json()["data"]
        return job_id

    ###########################################
    ### Families 
    ###########################################

    def getFamily(self, family_id: int) -> Optional[str]:
        response = requests.get(f"{self.mcrit_server}/families/{family_id}")
        if response.status_code == 404:
            return None
        data = response.json()["data"]
        family_data = data[str(family_id)]
        return {
            "family_id": family_data["family_id"],
            "family": family_data["family"],
            "num_samples": family_data["num_samples"],
            "num_versions": family_data["num_versions"],
            "samples": [
                SampleEntry.fromDict(sample_entry_dict)
                for sample_entry_dict in sorted(family_data["samples"].values(), key=lambda s: s["sample_id"])
            ]
        }

    def getFamilies(self):
        result_data = requests.get(f"{self.mcrit_server}/families").json()["data"]
        return result_data

    ###########################################
    ### Samples 
    ###########################################

    def isSampleId(self, sample_id):
        response = requests.get(f"{self.mcrit_server}/samples/{sample_id}")
        if response.status_code == 404:
            return False
        return True

    def deleteSample(self, sample_id):
        response = requests.delete(f"{self.mcrit_server}/samples/{sample_id}")
        return response.json()["data"]

    def getSamplesByFamilyId(self, family_id: int) -> Optional[List[SampleEntry]]:
        response = requests.get(f"{self.mcrit_server}/families/{family_id}")
        if response.status_code == 404:
            return None
        data = response.json()["data"][str(family_id)]
        return [
            SampleEntry.fromDict(sample_entry_dict)
            for sample_entry_dict in data["samples"].values()
        ]

    def getSampleById(self, sample_id):
        response = requests.get(f"{self.mcrit_server}/samples/{sample_id}")
        if response.status_code == 404:
            return None
        data = response.json()
        if data["status"] == "successful":
            return SampleEntry.fromDict(data["data"])
        return {}

    def getSamples(self, start=0, limit=0):
        query_string = ""
        if (isinstance(start, int) and start >= 0) and (isinstance(limit, int) and limit >= 0):
            query_string = f"?start={start}&limit={limit}"
        data = requests.get(f"{self.mcrit_server}/samples{query_string}").json()["data"]
        return {int(k): SampleEntry.fromDict(v) for k, v in data.items()}

    ###########################################
    ### Functions
    ###########################################

    def getFunctionsBySampleId(self, sample_id):
        response = requests.get(f"{self.mcrit_server}/samples/{sample_id}/functions")
        if response.status_code == 404:
            return None
        data = response.json()["data"]
        return [
            FunctionEntry.fromDict(function_entry_dict)
            for function_entry_dict in data.values()
        ]

    def getFunctions(self, start=0, limit=0):
        query_string = ""
        if (isinstance(start, int) and start >= 0) and (isinstance(limit, int) and limit >= 0):
            query_string = f"?start={start}&limit={limit}"
        response = requests.get(f"{self.mcrit_server}/functions{query_string}")
        if response.status_code == 404:
            return None
        data = response.json()["data"]
        return {int(k): FunctionEntry.fromDict(v) for k, v in data.items()}

    def isFunctionId(self, function_id):
        response = requests.get(f"{self.mcrit_server}/functions/{function_id}")
        if response.status_code == 404:
            return False
        return True

    def getFunctionById(self, function_id: int) -> Optional[FunctionEntry]:
        response = requests.get(f"{self.mcrit_server}/functions/{function_id}")
        if response.status_code == 404:
            return None
        data = response.json()["data"]
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
        params = self._getMatchingRequestParams(
            minhash_threshold, pichash_size, force_recalculation
        )
        return requests.post(
            f"{self.mcrit_server}/query", json=smda_json, params=params
        ).json()["data"]

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
            return self.requestMatchesForSmdaReport(
                smda_report,
                minhash_threshold=minhash_threshold,
                pichash_size=pichash_size,
                force_recalculation=force_recalculation,
            )

        params = self._getMatchingRequestParams(
            minhash_threshold, pichash_size, force_recalculation
        )
        return requests.post(
            f"{self.mcrit_server}/query/binary/mapped/{base_address}",
            binary,
            params=params,
        ).json()["data"]

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
            return self.requestMatchesForSmdaReport(
                smda_report,
                minhash_threshold=minhash_threshold,
                pichash_size=pichash_size,
                force_recalculation=force_recalculation,
            )

        params = self._getMatchingRequestParams(
            minhash_threshold, pichash_size, force_recalculation
        )
        return requests.post(
            f"{self.mcrit_server}/query/binary", binary, params=params
        ).json()["data"]

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
        return requests.get(
            f"{self.mcrit_server}/matches/sample/{sample_id}", params=params
        ).json()["data"]

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
        return requests.get(
            f"{self.mcrit_server}/matches/sample/{sample_id}/{other_sample_id}",
            params=params,
        ).json()["data"]

    ###########################################
    ### Status, Results 
    ###########################################

    def getStatus(self):
        response = requests.get(f"{self.mcrit_server}/status")
        return response.json()["data"]

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
        jobs = requests.get(f"{self.mcrit_server}/jobs/{query_string}").json()
        return [Job(job_data, None) for job_data in jobs]

    def getJobData(self, job_id):
        response = requests.get(f"{self.mcrit_server}/jobs/{job_id}")
        if response.status_code != 200:
            return None
        job_data = response.json()["data"]
        return Job(job_data, None)

    def getResultForJob(self, job_id):
        response = requests.get(f"{self.mcrit_server}/jobs/{job_id}/result")
        if response.status_code != 200:
            return None
        result_data = response.json()["data"]
        return result_data

    def getResult(self, result_id):
        result_data = requests.get(f"{self.mcrit_server}/results/{result_id}").json()
        return result_data

    def awaitResult(self, job_id, sleep_time=2):
        if job_id is None:
            return None
        job = self.getJobData(job_id)
        while not isJobFinishedOrTerminated(job):
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
                result_data = requests.get(f"{self.mcrit_server}/export/{sample_ids_as_str}{compress_uri_param}").json()["data"]
            else:
                raise ValueError("sample_ids must be a list of int.")
        else:
            result_data = requests.get(f"{self.mcrit_server}/export{compress_uri_param}").json()["data"]
        return result_data

    def addImportData(self, import_data):
        if not isinstance(import_data, dict):
            raise ValueError("Can only forward dictionaries with export data.")
        result_data = requests.post(f"{self.mcrit_server}/import", json=import_data).json()["data"]
        return result_data

    ###########################################
    ### Search
    ###########################################

    def search(self, search_term):
        result_data = requests.get(f"{self.mcrit_server}/search/{search_term}").json()["data"]
        return result_data
