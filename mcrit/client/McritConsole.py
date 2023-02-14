import os
import re
import json
import hashlib
import argparse

from smda.Disassembler import Disassembler
from smda.common.SmdaReport import SmdaReport

from mcrit.client.McritClient import McritClient


### Helper functionality for submissions

def is_pe_or_elf(input_path):
    """
    Don't perform a full validation, just check heuristically if the file starts with PE or ELF markings
    """
    data = b""
    with open(input_path, "rb") as fin:
        data = fin.read(4)
    if len(data) >= 4:
        is_elf = data[:4] == b"\x7FELF"
        is_pe = data[:2] == b"MZ"
        return is_elf or is_pe
    return False


def get_base_addr(input_path):
    """
    If provided path ends with 0x[0-9a-fA-F]{8,16}, we assume that this is an IMAGEBASE address. 
    """
    base_addr = None
    baddr_match = re.search(re.compile("0x(?P<base_addr>[0-9a-fA-F]{8,16})$"), input_path)
    if baddr_match:
        base_addr = int(baddr_match.group("base_addr"), 16)
    return base_addr


def sha256(content):
    return hashlib.sha256(content).hexdigest()


def readFileContent(file_path):
    file_content = b""
    with open(file_path, "rb") as fin:
        file_content = fin.read()
    return file_content


def getFamilyName(input_path):
    family_name = ""
    abs_path = os.path.abspath(input_path)
    for folder in abs_path.split("/")[::-1]:
        if folder:
            family_name = folder
    return family_name


def getSampleVersion(input_path, family):
    sample_version = ""
    collected = []
    for folder in input_path.split("/"):
        if folder != family and folder != "":
            collected.append(folder)
    if collected:
        sample_version = os.sep.join(collected)
    return sample_version


def getFolderFilePath(input_root, input_path):
    abs_path = os.path.abspath(input_path)
    relative_filepath = abs_path[len(input_root):]
    return relative_filepath


def getSmdaReportFromFilepath(args, filepath):
    filename = os.path.basename(filepath)
    smda_report = None
    if args.smda:
        if not filename.endswith(".smda"):
            print(f"Skipping a file not recognized as SMDA report: {filepath}")
        else:
            try:
                smda_report = SmdaReport.fromFile(filepath)
            except:
                print(f"Failed to parse SMDA report: {filepath}")
    else:
        if args.executables_only and not is_pe_or_elf(filepath):
            print(f"Skipping a file not recognized as executable: {filepath}")
        else:
            disassembler = Disassembler()
            if get_base_addr(filename) is not None:
                base_addr = get_base_addr(filename)
                smda_report = disassembler.disassembleBuffer(readFileContent(filepath), base_addr)
                smda_report.filename = filename
            else:
                smda_report = disassembler.disassembleFile(filepath)
    # apply any of the forced flags: family, version, library
    if smda_report:
        if args.mode in ["file", "dir"]:
            if args.family is not None:
                smda_report.family = args.family
            if args.version is not None:
                smda_report.version = args.version
        if args.mode in ["file", "dir", "recursive"] and args.library:
            smda_report.is_library = True
        if args.output:
            with open() as f_smda:
                json.dump(smda_report.toDict(), f_smda, sort_keys=True, indent=1)
    return smda_report



### Main Processing 

class McritConsole(object):

    def __init__(self) -> None:
        self.parser = argparse.ArgumentParser(description="Console interaction with MCRIT.")
        subparsers = self.parser.add_subparsers(dest="command")
        self.parser_client = subparsers.add_parser("client")
        subparser_client = self.parser_client.add_subparsers(dest="client_command")
        client_status = subparser_client.add_parser("status")
        # client submit
        client_submit = subparser_client.add_parser("submit", help="Various ways of file submission incl. disassembly using SMDA if needed.")
        client_submit.add_argument("filepath", type=str, help="Submit the folllowing <filepath>, indicating a (file/dir).")
        client_submit.add_argument("--mode", type=str, default="file", choices=["file", "dir", "recursive", "malpedia"], help="Submit a single <file> or all files in a <dir>. Use <recursive> submission for a folder structured as ./family_name/version/version/files. Synchronize <malpedia> into MCRIT. Default: <file>.")
        client_submit.add_argument("-f", "--family", type=str, help="Set/Override SmdaReport with this family (only in modes: file/dir)")
        client_submit.add_argument("-v", "--version", type=str, help="Set/Override SmdaReport with this version (only in modes: file/dir)")
        client_submit.add_argument("-l", "--library", action="store_true", help="Set/Override SmdaReport with the library flag (only in modes: file/dir/recursive, default: False).")
        client_submit.add_argument("-x", "--executables_only", action="store_true", help="Only process files that are parsable PE or ELF files (default: False).")
        client_submit.add_argument("-o", "--output", type=str, help="Optionally store SMDA reports in folder OUTPUT.")
        client_submit.add_argument("-s", "--smda", action="store_true", help="Do not disassemble, instead only submit files that are recognized as SMDA reports (only works with modes: file/dir).")
        # client import 
        client_import = subparser_client.add_parser("import", help="Import of previously exported data in the MCRIT format.")
        client_import.add_argument("filepath", type=str, help="Import a given <filepath> containing MCRIT data into the storage.")
        client_export = subparser_client.add_parser("export", help="Export of data from MCRIT.")
        client_export.add_argument("filepath", type=str, help="Export the full storage into <filepath>.")
        client_export.add_argument("--sample_ids", type=str, help="Limit export to a list of comma-separated <sample_ids>.")
        client_search = subparser_client.add_parser("search", help="Search for arbitrary data based on a search string.")
        client_search.add_argument("search_term", type=str, help="Conduct a search with a given <search_term>.")
        client_queue = subparser_client.add_parser("queue", help="Inspection of the current processing queue.")
        client_queue.add_argument("--filter", type=str, help="Filter queue entries with this term.")

    def run(self):
        ARGS = self.parser.parse_args()
        if ARGS.client_command == "status":
            self._handle_status(ARGS)
        elif ARGS.client_command == "import":
            self._handle_import(ARGS)
        elif ARGS.client_command == "export":
            self._handle_export(ARGS)
        elif ARGS.client_command == "search":
            self._handle_search(ARGS)
        elif ARGS.client_command == "queue":
            self._handle_queue(ARGS)
        elif ARGS.client_command == "submit":
            self._handle_submit(ARGS)
        elif ARGS.client_command == "sync":
            self._handle_sync(ARGS)
        else:
            print(self.parser_client.print_help())

    def _handle_status(self, args):
        client = McritClient()
        result = client.getStatus()
        print(result)

    def _handle_import(self, args):
        client = McritClient()
        if os.path.isfile(args.filepath):
            with open(args.filepath) as fin:
                result = client.addImportData(json.load(fin))
                print(result)

    def _handle_export(self, args):
        client = McritClient()
        sample_ids = None
        if args.sample_ids is not None:
            sample_ids = [int(i) for i in args.sample_ids.split(",")]
        result = client.getExportData(sample_ids=sample_ids)
        with open(args.filepath, "w") as fout:
            json.dump(result, fout, indent=1)
        print(f"wrote export to {args.filepath}.")

    def _handle_search(self, args):
        client = McritClient()
        result = client.search(args.search_term)
        print(result)

    def _handle_queue(self, args):
        client = McritClient()
        result = client.getQueueData(filter=args.filter)
        for entry in result:
            job_id = entry.job_id
            result_id = entry.result
            created = entry.created_at if entry.created_at is not None else "-"
            started = entry.started_at if entry.started_at is not None else "-"
            finished = entry.finished_at if entry.finished_at is not None else "-"
            method = entry.parameters
            progress = entry.progress
            print(f"{job_id} {result_id} | {created} {started} {finished} | {method} - {progress}")

    def _handle_submit(self, args):
        # run a number of sanity checks first
        if not os.path.exists(args.filepath):
            print("Your <filepath> does not exist.")
            return
        if args.mode == "file" and not os.path.isfile(args.filepath):
            print("Mode <file> only works when <filepath> is a file.")
            return
        if args.mode in ["dir", "recursive", "malpedia"] and not os.path.isdir(args.filepath):
            print("Modes <dir|recursive|malpedia> only work when <filepath> is a directory.")
            return
        if args.output is not None and (not os.path.exists(args.output) or not os.path.isdir(args.output)):
            print("Your <output> is not a directory or does not exist.")
            return
        if args.smda and args.mode in ["recursive", "malpedia"]:
            print("Modes <recursive|malpedia> are not compatible with SMDA report loading.")
            return
        # behavior according to the modes offered
        if args.mode == "file":
            self._handle_submit_file(args)
        if args.mode == "dir":
            self._handle_submit_dir(args)
        if args.mode == "recursive":
            self._handle_submit_recursive(args)
        if args.mode == "malpedia":
            self._handle_submit_malpedia(args)

    def _handle_submit_file(self, args):
        client = McritClient()
        mcrit_samples = client.getSamples()
        mcrit_samples_by_sha256 = {}
        for sample_id, sample in mcrit_samples.items():
            mcrit_samples_by_sha256[sample.sha256] = sample
        if sha256(readFileContent(args.filepath)) in mcrit_samples_by_sha256:
            print(f"SKIPPING: {args.filepath} - already in MCRIT.")
        smda_report = getSmdaReportFromFilepath(args, args.filepath)
        if smda_report:
            print(smda_report)
            client.addReport(smda_report)

    def _handle_submit_dir(self, args):
        client = McritClient()
        mcrit_samples = client.getSamples()
        mcrit_samples_by_sha256 = {}
        for sample_id, sample in mcrit_samples.items():
            mcrit_samples_by_sha256[sample.sha256] = sample
        for filename in os.listdir(args.filepath):
            filepath = os.sep.join([args.filepath, filename])
            if os.path.isfile(filepath):
                if os.path.isfile(filepath):
                    if sha256(readFileContent(filepath)) in mcrit_samples_by_sha256:
                        print(f"SKIPPING: {filepath} - already in MCRIT.")
                        continue
                smda_report = getSmdaReportFromFilepath(args, filepath)
                if smda_report:
                    print(smda_report)
                    client.addReport(smda_report)

    def _handle_submit_recursive(self, args):
        client = McritClient()
        mcrit_samples = client.getSamples()
        mcrit_samples_by_sha256 = {}
        for sample_id, sample in mcrit_samples.items():
            mcrit_samples_by_sha256[sample.sha256] = sample
        for root, subdir, files in sorted(os.walk(args.filepath)):
            folder_relative_path = getFolderFilePath(args.filepath, root)
            for filename in files:
                filepath = os.sep.join([root, filename])
                if os.path.isfile(filepath):
                    if sha256(readFileContent(filepath)) in mcrit_samples_by_sha256:
                        print(f"SKIPPING: {filepath} - already in MCRIT.")
                        continue
                    smda_report = getSmdaReportFromFilepath(args, filepath)
                    if smda_report:
                        smda_report.family = getFamilyName(folder_relative_path)
                        smda_report.version = getSampleVersion(folder_relative_path, smda_report.family)
                        print(filepath)
                        print(smda_report)
                        client.addReport(smda_report)

    def _handle_submit_malpedia(self, args):
        client = McritClient()
        # get current status of all samples in MCRIT
        mcrit_samples = client.getSamples()
        mcrit_samples_by_filename = {}
        for sample_id, sample in mcrit_samples.items():
            # verify that filename has malpedia format (starts with sha256 and _unpacked/_dump)
            if sample.filename in mcrit_samples_by_filename:
                print(f"WARNING: filename {sample.filename} appears to exist more than once in your MCRIT instance, now using SHA256 {sample.sha256[:8]}.")
            mcrit_samples_by_filename[sample.filename] = sample
        # get all unpacked/dumped files and their family/version by crawling given Malpedia location
        malpedia_samples_by_filename = self._getMalpediaSamplesByFilename(args.filepath)
        # use submission filenames within MCRIT to check for presence of files and verify their family/version identity
        for filename, malpedia_info in malpedia_samples_by_filename.items():
            malpedia_family = malpedia_info["family"]
            malpedia_version = malpedia_info["version"]
            malpedia_filepath = malpedia_info["filepath"]
            if filename in mcrit_samples_by_filename:
                mcrit_family = mcrit_samples_by_filename[filename].family
                mcrit_version = mcrit_samples_by_filename[filename].version
                # warn about files were family/version mismatches.
                if (malpedia_family != mcrit_family or
                        malpedia_version != mcrit_version):
                    print(f"WARNING: Sample {mcrit_samples_by_filename[filename].sample_id} with filename {filename} has different family/version information: ")
                    print(f"* Malpedia: {malpedia_family}|{malpedia_version}")
                    print(f"* MCRIT: {mcrit_family}|{mcrit_version}")
            # directly add all files in Malpedia but missing in MCRIT
            else:
                smda_report = getSmdaReportFromFilepath(args, malpedia_filepath)
                if smda_report:
                    smda_report.family = malpedia_family
                    smda_report.version = malpedia_version
                    print(malpedia_filepath)
                    print(smda_report)
                    client.addReport(smda_report)
        # warn about files that appear deleted because not present in Malpedia but in MCRIT (based on name schea)
        for filename, mcrit_sample in mcrit_samples_by_filename.items():
            if self._isMalpediaFilename(filename) and filename not in malpedia_samples_by_filename:
                print(f"WARNING: Sample {mcrit_sample.sample_id} with filename {filename} ({mcrit_sample.family}|{mcrit_sample.version}) present in MCRIT but not in Malpedia?")

    def _getMalpediaSamplesByFilename(self, malpedia_root):
        malpedia_samples_by_filename = {}
        for root, subdir, files in sorted(os.walk(malpedia_root)):
            folder_relative_path = getFolderFilePath(malpedia_root, root)
            for filename in sorted(files):
                if self._isMalpediaFilename(filename):
                    filepath = root + os.sep + filename
                    sample_family = getFamilyName(folder_relative_path)
                    malpedia_samples_by_filename[filename] = {
                        "filename": filename,
                        "filepath": filepath,
                        "family": sample_family,
                        "version": getSampleVersion(folder_relative_path, sample_family)
                    }
        return malpedia_samples_by_filename
    
    def _isMalpediaFilename(self, filename):
        malpedia_file_pattern = re.compile("^[0-9a-f]{64}(_unpacked|dump7?_0x[0-9a-fA-F]{8,16})")
        return re.search(malpedia_file_pattern, filename)
