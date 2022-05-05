import argparse
import hashlib
import json
import os
import re
import sys
from copy import deepcopy

from smda.common.SmdaReport import SmdaReport
from smda.Disassembler import Disassembler

from mcrit.client.McritClient import McritClient


def send_report(smda_report: SmdaReport, query=False, mcrit_server=None):
    client = McritClient(mcrit_server=mcrit_server)
    # curl -X POST --data-binary "@$1" 127.0.0.1:8000/samples -H "Content-Type: application/json"
    if query:
        job_id = client.requestMatchesForSmdaReport(smda_report)
        sample_summary = client.awaitResult(job_id)["matches"]["samples"]
        match_index = 0
        for entry in sorted(sample_summary, key=lambda x: x["matched"]["percent"]["unweighted"], reverse=True):
            match_index += 1
            print(
                f"{match_index}) {entry['sample_id']:>4} | {entry['family']:>12} {entry['version']:>30} ({entry['bitness']:>2}bit) - {entry['sha256']}: {entry['matched']['functions']['minhashes']:>5}, {entry['matched']['functions']['pichashes']:>5}, {entry['matched']['functions']['combined']:>5}, {entry['matched']['functions']['library']:>5}, {entry['matched']['bytes']['score_weighted']:>8}, {entry['matched']['percent']['unweighted']:>6.2f}%"
            )

    else:
        client.addReport(smda_report)


def load_reports_from_path(filepath):
    smda_reports = []
    if os.path.isdir(filepath):
        for filename in sorted(os.listdir(filepath)):
            smda_filepath = filepath + os.sep + filename
            if os.path.isfile(smda_filepath) and smda_filepath.endswith(".smda"):
                smda_reports.append(SmdaReport.fromFile(smda_filepath))
    elif os.path.isfile(filepath) and filepath.endswith(".smda"):
        smda_reports = [SmdaReport.fromFile(filepath)]
    return smda_reports



def get_base_addr(input_path):
    base_addr = None
    baddr_match = re.search(re.compile("0x(?P<base_addr>[0-9a-fA-F]{8,16})$"), input_path)
    if baddr_match:
        base_addr = int(baddr_match.group("base_addr"), 16)
    return base_addr


def readFileContent(file_path):
    file_content = b""
    with open(file_path, "rb") as fin:
        file_content = fin.read()
    return file_content


def main(argv):
    argparser = argparse.ArgumentParser(
        description="Add SMDA reports to an MCRIT index."
    )
    argparser.add_argument(
        "-r", "--recursive", action="store_true", default=False, help="Iterate recursively over a given root folder."
    )
    argparser.add_argument(
        "-q", "--query", action="store_true", default=False, help="Query the report instead of submitting it"
    )
    argparser.add_argument(
        "-d",
        "--disassemble",
        action="store_true",
        default=False,
        help="Disassemble a given file using SMDA before submission.",
    )
    argparser.add_argument(
        "input_path", type=str, default="", help="Root folder to scan for SMDA reports or a single SMDA report file."
    )
    if len(argv) < 2:
        argparser.print_help()
        return 1

    ARGS = argparser.parse_args()
    if ARGS.input_path and os.path.exists(ARGS.input_path):
        if os.path.isfile(ARGS.input_path):
            if ARGS.disassemble:
                disassembler = Disassembler()
                if get_base_addr(ARGS.input_path) is not None:
                    base_addr = get_base_addr(ARGS.input_path)
                    smda_report = disassembler.disassembleBuffer(readFileContent(ARGS.input_path), base_addr)
                    smda_report.filename = os.path.basename(ARGS.input_path)
                else:
                    smda_report = disassembler.disassembleFile(ARGS.input_path)
            else:
                smda_report = SmdaReport.fromFile(ARGS.input_path)
            print(smda_report)
            send_report(smda_report, query=ARGS.query)
        elif os.path.isdir(ARGS.input_path):
            if ARGS.recursive:
                for root, subdir, files in sorted(os.walk(ARGS.input_path)):
                    if ARGS.disassemble:
                        for filename in files:
                            filepath = root + os.sep + filename
                            disassembler = Disassembler()
                            if get_base_addr(filepath) is not None:
                                base_addr = get_base_addr(filepath)
                                smda_report = disassembler.disassembleBuffer(readFileContent(filepath), base_addr)
                                smda_report.filename = os.path.basename(filepath)
                            else:
                                smda_report = disassembler.disassembleFile(filepath)
                            print(smda_report)
                            send_report(smda_report, query=ARGS.query)
                    else:
                        for filename in files:
                            filepath = ARGS.input_path + os.sep + filename
                            try:
                                smda_report = SmdaReport.fromFile(filepath)
                                print(smda_report)
                                send_report(smda_report, query=ARGS.query)
                            except:
                                print("failed with report: ", filepath)
            else:
                if ARGS.disassemble:
                    for filename in os.listdir(ARGS.input_path):
                        filepath = ARGS.input_path + os.sep + filename
                        disassembler = Disassembler()
                        if get_base_addr(filepath) is not None:
                            base_addr = get_base_addr(filepath)
                            smda_report = disassembler.disassembleBuffer(readFileContent(filepath), base_addr)
                            smda_report.filename = os.path.basename(filepath)
                        else:
                            smda_report = disassembler.disassembleFile(filepath)
                        print(smda_report)
                        send_report(smda_report, query=ARGS.query)
                else:
                    for filename in os.listdir(ARGS.input_path):
                        filepath = ARGS.input_path + os.sep + filename
                        try:
                            smda_report = SmdaReport.fromFile(filepath)
                            print(smda_report)
                            send_report(smda_report, query=ARGS.query)
                        except:
                            print("failed with report: ", filepath)
        else:
            argparser.print_help()
    else:
        argparser.print_help()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
