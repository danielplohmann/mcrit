import json
import os
import sys
import requests

try:
    from smda.Disassembler import Disassembler
    from smda.ida.IdaInterface import IdaInterface
except:
    print("SMDA not found, please install it (and its dependencies) as a python package to proceed!")
    sys.exit()
#from helpers.SmdaConfig import SmdaConfig

from mcrit.client.McritClient import McritClient


class McritInterface(object):

    def __init__(self, parent):
        self.parent = parent
        self.config = parent.config
        self._mcrit_server = self.config.MCRIT_SERVER
        self.mcrit_client = McritClient(self.config.MCRIT_SERVER)
        if self.config.MCRITWEB_API_TOKEN:
            self.mcrit_client.setApitoken(self.config.MCRITWEB_API_TOKEN)
        if self.config.MCRITWEB_USERNAME:
            self.mcrit_client.setApitoken(self.config.MCRITWEB_USERNAME)
        #self.smda_config = SmdaConfig()
        self.smda_disassembler = Disassembler(backend="IDA")
        self.smda_ida = IdaInterface()
        # IDA 6.x Windows workaronud to avoid lost imports
        self.json = json
        self.os = os
        self.os_path = os.path

    def _getMcritServerAddress(self):
        return self._mcrit_server

    def convertIdbToSmda(self):
        self.parent.local_widget.updateActivityInfo("Converting to SMDA report...")
        report = self.smda_disassembler.disassembleBuffer(self.smda_ida.getBinary(), 0)
        self.parent.local_widget.updateActivityInfo("Conversion from IDB to SMDA finished.")
        return report

    def checkConnection(self):
        self.parent.local_widget.updateActivityInfo("Checking connection to server: %s" % self._getMcritServerAddress())
        try:
            mcrit_version = self.mcrit_client.getVersion()
            if mcrit_version:
                self.parent.local_widget.updateActivityInfo("Connection check successful!")
                self.parent.local_widget.updateServerInfo(self._getMcritServerAddress(), version=mcrit_version)
            else:
                self.parent.local_widget.updateActivityInfo("Connection check failed (status code).")
                self.parent.local_widget.updateServerInfo(self._getMcritServerAddress())
        except Exception as exc:
            import traceback
            print(traceback.format_exc(exc))
            self.parent.local_widget.updateActivityInfo("Connection check failed (unreachable).")
            self.parent.local_widget.updateServerInfo(self._getMcritServerAddress())

    def querySampleSha256(self, sha256):
        self.parent.local_widget.updateActivityInfo("Querying for SHA256")
        try:
            sample_by_sha256 = self.mcrit_client.getSampleBySha256(sha256)
            if sample_by_sha256:
                self.parent.remote_sample_entry = sample_by_sha256
                self.parent.local_widget.updateActivityInfo("Success! Received remote Sample Entry.")
            else:
                self.parent.local_widget.updateActivityInfo("querySampleSha256 failed")
        except Exception as exc:
            import traceback
            print(traceback.format_exc(exc))
            self.parent.local_widget.updateActivityInfo("querySampleSha256 failed, error on connection :(")
            self.parent.local_widget.updateServerInfo(self._getMcritServerAddress())

    def uploadReport(self, report):
        self.parent.local_widget.updateActivityInfo("Sending SMDA report to server %s" % self._getMcritServerAddress())
        try:
            sample_entry, job_id = self.mcrit_client.addReport(report)
            if sample_entry:
                if job_id:
                    self.parent.local_widget.updateActivityInfo("Upload finished, remote sample_id is: %d (processing MinHashes as job_id: %s)" % (sample_entry.sample_id, job_id))
                else:
                    self.parent.local_widget.updateActivityInfo("Upload finished, remote sample_id is: %d." % sample_entry.sample_id)
                self.parent.remote_sample_entry = sample_entry
                self.parent.local_widget.update()
            else:
                self.parent.local_widget.updateActivityInfo("Upload failed.")
        except Exception as exc:
            import traceback
            print(traceback.format_exc(exc))
            self.parent.local_widget.updateActivityInfo("Upload failed, error on connection :(")
            self.parent.local_widget.updateServerInfo(self._getMcritServerAddress())

    def queryMatchReport(self, sample_id):
        # TODO revise this workflow
        raise NotImplementedError
        self.parent.local_widget.updateActivityInfo("Querying matches for sample with id: %d" % self.parent.remote_sample_id)
        try:
            response = requests.get(self._getMcritServerAddress() + "/samples/%d/matches" % sample_id)
            if response.status_code == 200:
                response_json = response.json()
                response_content = response_json["data"]
                self.parent.matching_report = response_content
                self.parent.local_widget.updateActivityInfo("Success! Fetched matches.")
            else:
                self.parent.local_widget.updateActivityInfo("Match query failed, status code: %d." % response.status_code)
        except Exception as exc:
            import traceback
            print(traceback.format_exc(exc))
            self.parent.local_widget.updateActivityInfo("Match query failed, error on connection :(")
            self.parent.local_widget.updateServerInfo(self._getMcritServerAddress())

    def queryAllFamilyEntries(self):
        self.parent.local_widget.updateActivityInfo("Querying for FamilyEntries")
        try:
            family_entries = self.mcrit_client.getFamilies()
            if family_entries:
                self.parent.family_infos = family_entries
                self.parent.local_widget.updateActivityInfo("Success! Received all remote FamilyEntries.")
            else:
                self.parent.local_widget.updateActivityInfo("queryAllFamilyEntries failed")
        except Exception as exc:
            import traceback
            print(traceback.format_exc(exc))
            self.parent.local_widget.updateActivityInfo("queryAllFamilyEntries failed, error on connection :(")
            self.parent.local_widget.updateServerInfo(self._getMcritServerAddress())

    def querySmdaFunctionMatches(self, smda_report):
        try:
            smda_function = [f for f in smda_report.getFunctions()][0]
            if smda_function.offset not in self.parent.function_matches:
                match_report = self.mcrit_client.getMatchesForSmdaFunction(smda_report, exclude_self_matches=False)
                if match_report:
                    self.parent.function_matches.update({smda_function.offset: match_report})
        except Exception as exc:
            import traceback
            print(traceback.format_exc(exc))
            self.parent.local_widget.updateActivityInfo("querySmdaFunctionMatches failed, error on connection :(")
            self.parent.local_widget.updateServerInfo(self._getMcritServerAddress())

    def queryFunctionEntriesById(self, function_ids):
        try:
            return self.mcrit_client.getFunctionsByIds(function_ids)
        except Exception as exc:
            import traceback
            print(traceback.format_exc(exc))
            self.parent.local_widget.updateActivityInfo("queryFunctionEntriesById failed, error on connection :(")
            self.parent.local_widget.updateServerInfo(self._getMcritServerAddress())

    def queryPicHashMatches(self, pichash):
        try:
            if pichash not in self.parent.pichash_matches:
                pichash_matches = self.mcrit_client.getMatchesForPicHash(pichash)
                if pichash_matches:
                    self.parent.pichash_matches.update({pichash: pichash_matches})
                pichash_match_summary = self.mcrit_client.getMatchesForPicHash(pichash, summary=True)
                if pichash_match_summary:
                    self.parent.pichash_match_summaries.update({pichash: pichash_match_summary})
        except Exception as exc:
            import traceback
            print(traceback.format_exc(exc))
            self.parent.local_widget.updateActivityInfo("queryPicHashMatches failed, error on connection :(")
            self.parent.local_widget.updateServerInfo(self._getMcritServerAddress())

    def queryAllSampleEntries(self):
        self.parent.local_widget.updateActivityInfo("Querying for SampleEntries")
        try:
            sample_entries = self.mcrit_client.getSamples()
            if sample_entries:
                self.parent.sample_infos = sample_entries
                self.parent.local_widget.updateActivityInfo("Success! Received all remote SampleEntries.")
            else:
                self.parent.local_widget.updateActivityInfo("queryAllSampleEntries query failed")
        except Exception as exc:
            import traceback
            print(traceback.format_exc(exc))
            self.parent.local_widget.updateActivityInfo("queryAllSampleEntries failed, error on connection :(")
            self.parent.local_widget.updateServerInfo(self._getMcritServerAddress())

    def queryFunctionEntriesBySampleId(self, sample_id):
        self.parent.local_widget.updateActivityInfo("Querying for remote FunctionEntry mapping")
        try:
            functions_for_sample = self.mcrit_client.getFunctionsBySampleId(sample_id)
            if functions_for_sample:
                self.parent.remote_function_mapping = {function_entry.function_id: function_entry for function_entry in functions_for_sample}
                self.parent.local_widget.updateActivityInfo("Success! Fetched remote FunctionEntry mapping.")
            else:
                self.parent.local_widget.updateActivityInfo("queryFunctionEntriesBySampleId query failed.")
        except Exception as exc:
            import traceback
            print(traceback.format_exc(exc))
            self.parent.local_widget.updateActivityInfo("queryFunctionEntriesBySampleId failed, error on connection :(")
            self.parent.local_widget.updateServerInfo(self._getMcritServerAddress())
