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


class McritInterface(object):

    def __init__(self, parent):
        self.parent = parent
        self.config = parent.config
        self._mcrit_server = self.config.MCRIT_SERVER
        self._mcrit_port = self.config.MCRIT_PORT
        self._mcrit_database = self.config.MCRIT_DBNAME
        #self.smda_config = SmdaConfig()
        self.smda_disassembler = Disassembler(backend="IDA")
        self.smda_ida = IdaInterface()
        # IDA 6.x Windows workaronud to avoid lost imports
        self.json = json
        self.os = os
        self.os_path = os.path

    def _getMcritServerAddress(self):
        return "http://%s:%s" % (self._mcrit_server, self._mcrit_port)

    def convertIdbToSmda(self):
        self.parent.local_widget.updateActivityInfo("Converting to SMDA report...")
        report = self.smda_disassembler.disassembleBuffer(self.smda_ida.getBinary(), 0)
        self.parent.local_widget.updateActivityInfo("Conversion from IDB to SMDA finished.")
        return report.toDict()

    def checkConnection(self):
        self.parent.local_widget.updateActivityInfo("Checking connection to server: %s" % self._getMcritServerAddress())
        try:
            response = requests.get(self._getMcritServerAddress() + "/status")
            if response.status_code == 200:
                response_json = response.json()
                response_content = response_json["data"]["status"]
                self.parent.local_widget.updateActivityInfo("Connection check successful!")
                self.parent.local_widget.updateServerInfo(self._getMcritServerAddress(), self._mcrit_database, status=response_content)
            else:
                self.parent.local_widget.updateActivityInfo("Connection check failed (status code).")
                self.parent.local_widget.updateServerInfo(self._getMcritServerAddress(), self._mcrit_database)
        except Exception as exc:
            import traceback
            print(traceback.format_exc(exc))
            self.parent.local_widget.updateActivityInfo("Connection check failed (unreachable).")
            self.parent.local_widget.updateServerInfo(self._getMcritServerAddress(), self._mcrit_database)

    def uploadReport(self, report):
        self.parent.local_widget.updateActivityInfo("Sending SMDA report to server %s" % self._getMcritServerAddress())
        try:
            response = requests.post(self._getMcritServerAddress() + "/samples", json=report)
            if response.status_code == 200:
                response_json = response.json()
                response_content = response_json["data"]
                self.parent.mcrit_interface.checkConnection()
                self.parent.local_widget.updateActivityInfo("Upload finished, sample_id is: %d." % response_content["sample_info"]["sample_id"])
                self.parent.remote_sample_id = response_content["sample_info"]["sample_id"]
            else:
                self.parent.local_widget.updateActivityInfo("Upload failed, status code: %d." % response.status_code)
        except Exception as exc:
            import traceback
            print(traceback.format_exc(exc))
            self.parent.local_widget.updateActivityInfo("Upload failed, error on connection :(")
            self.parent.local_widget.updateServerInfo(self._getMcritServerAddress(), self._mcrit_database)

    def queryMatchReport(self, sample_id):
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
            self.parent.local_widget.updateServerInfo(self._getMcritServerAddress(), self._mcrit_database)

    def querySampleInfos(self):
        self.parent.local_widget.updateActivityInfo("Querying for sample infos")
        try:
            response = requests.get(self._getMcritServerAddress() + "/samples")
            if response.status_code == 200:
                response_json = response.json()
                response_content = response_json["data"]
                self.parent.sample_infos = {int(sample["sample_id"]): sample for sample in response_content["samples"]}
                self.parent.local_widget.updateActivityInfo("Success! Fetched remote sample infos.")
            else:
                self.parent.local_widget.updateActivityInfo("Sample info query failed, status code: %d." % response.status_code)
        except Exception as exc:
            import traceback
            print(traceback.format_exc(exc))
            self.parent.local_widget.updateActivityInfo("Sample info query failed, error on connection :(")
            self.parent.local_widget.updateServerInfo(self._getMcritServerAddress(), self._mcrit_database)

    def queryFunctionInfos(self, sample_id):
        self.parent.local_widget.updateActivityInfo("Querying for remote function id mapping")
        try:
            response = requests.get(self._getMcritServerAddress() + "/samples/%d/functions" % sample_id)
            if response.status_code == 200:
                response_json = response.json()
                response_content = response_json["data"]
                self.parent.remote_function_mapping = response_content
                self.parent.local_widget.updateActivityInfo("Success! Fetched remote function id mapping.")
            else:
                self.parent.local_widget.updateActivityInfo("Function info query failed, status code: %d." % response.status_code)
        except Exception as exc:
            import traceback
            print(traceback.format_exc(exc))
            self.parent.local_widget.updateActivityInfo("Function info query failed, error on connection :(")
            self.parent.local_widget.updateServerInfo(self._getMcritServerAddress(), self._mcrit_database)
