import argparse
import csv
import hashlib
import json
import os
import re
import shutil
import sys
import time
from collections import defaultdict
from copy import deepcopy

import numpy as np
import tqdm
from fastcluster import linkage
from scipy.spatial.distance import squareform
from smda.common.SmdaReport import SmdaReport
from smda.Disassembler import Disassembler

from mcrit.matchers.MatcherInterface import IS_PICHASH_FLAG, IS_LIBRARY_FLAG
from mcrit.client.McritClient import McritClient


MATCHING_METHODS = [
    "unweighted", 
    "score_weighted", 
    "frequency_weighted",
    "nonlib_unweighted", 
    "nonlib_score_weighted", 
    "nonlib_frequency_weighted"
]


####################################################
#### HELPER FUNCTIONS FOR PROCESSING MATCH DATA ####
####################################################

def ensure_dir(path):
    try:
        os.makedirs(path)
    except:
        pass


def clear_dir(path):
    for filename in os.listdir(path):
        filepath = os.path.join(path, filename)
        try:
            shutil.rmtree(filepath)
        except OSError:
            os.remove(filepath)


def get_function_data_mapping(client: McritClient, sample_ids):
    function_id_to_data = {}
    for sample_id in sample_ids:
        functions = client.getFunctionsBySampleId(sample_id)
        for function_entry in functions:
            function_data = {
                "offset": function_entry.offset,
                "num_instructions": function_entry.num_instructions,
                "function_name": function_entry.function_name

            }
            function_id_to_data[function_entry.function_id] = function_data
    return function_id_to_data


def _aggregateMatchesPerSample(match_report):
    matches_per_sample = {}
    for function_match in match_report:
        own_function_id = function_match["fid"]
        is_library_match = False
        # check if there are any pichash+library matches
        for match_entry in function_match["matches"]:
            family_id, foreign_sample_id, foreign_function_id, score, flags = match_entry
            is_library_match |= (flags & IS_LIBRARY_FLAG) and (flags & IS_PICHASH_FLAG)
        for match_entry in function_match["matches"]:
            family_id, foreign_sample_id, foreign_function_id, score, flags = match_entry
            is_pic_hash = flags & IS_PICHASH_FLAG
            # propagate library matches that are pichash-matched
            if foreign_sample_id not in matches_per_sample:
                matches_per_sample[foreign_sample_id] = {}
            if own_function_id not in matches_per_sample[foreign_sample_id]:
                matches_per_sample[foreign_sample_id][own_function_id] = []
            match_type = "pichash" if is_pic_hash else "minhash"
            matches_per_sample[foreign_sample_id][own_function_id].append((match_type, score, foreign_function_id, is_library_match))
    return matches_per_sample


####################################################
#### HELPER FUNCTIONS FOR CLUSTERING THE MATRIX ####
####################################################

# based on hierachical clustering described in https://gmarti.gitlab.io/ml/2017/09/07/how-to-sort-distance-matrix.html


def seriation(Z, N, cur_index):
    """
    input:
        - Z is a hierarchical tree (dendrogram)
        - N is the number of points given to the clustering process
        - cur_index is the position in the tree for the recursive traversal
    output:
        - order implied by the hierarchical tree Z

    seriation computes the order implied by a hierarchical tree (dendrogram)
    """
    if cur_index < N:
        return [cur_index]
    else:
        left = int(Z[cur_index - N, 0])
        right = int(Z[cur_index - N, 1])
        return seriation(Z, N, left) + seriation(Z, N, right)


def compute_serial_matrix(dist_mat, method="ward"):
    """
    input:
        - dist_mat is a distance matrix
        - method = ["ward","single","average","complete"]
    output:
        - seriated_dist is the input dist_mat,
          but with re-ordered rows and columns
          according to the seriation, i.e. the
          order implied by the hierarchical tree
        - res_order is the order implied by
          the hierarchical tree
        - res_linkage is the hierarhical tree (dendrogram)

    compute_serial_matrix transforms a distance matrix into
    a sorted distance matrix according to the order implied
    by the hierarchical tree (dendrogram)
    """
    N = len(dist_mat)
    flat_dist_mat = squareform(dist_mat)
    res_linkage = linkage(flat_dist_mat, method=method, preserve_input=True)
    res_order = seriation(res_linkage, N, N + N - 2)
    seriated_dist = np.zeros((N, N))
    a, b = np.triu_indices(N, k=1)
    seriated_dist[a, b] = dist_mat[[res_order[i] for i in a], [res_order[j] for j in b]]
    seriated_dist[b, a] = seriated_dist[a, b]

    return seriated_dist, res_order, res_linkage


def calculate_clustered_sequence(matching_percent):
    # convert to dist_mat
    matrix_as_lists = []
    for sample_id, entries in sorted(matching_percent.items()):
        row = []
        for other_sample_id, percent in sorted(entries.items()):
            # we need a symmetric distance, so we use whatever distance is smaller for our sample pair
            distance = min(100 - percent, 100 - matching_percent[other_sample_id][sample_id])
            row.append(distance)
        matrix_as_lists.append(row)
    dist_mat = np.array(matrix_as_lists)
    # calculate clustering
    sorted_matrix, sorted_sequence, linkage = compute_serial_matrix(dist_mat, method="complete")
    # map sequence indices to sample_ids
    sample_id_sequence = sorted(matching_percent.keys())
    mapped_sequence = []
    for sorted_id in sorted_sequence:
        mapped_sequence.append(sample_id_sequence[sorted_id])
    return mapped_sequence

##########################################
#### HELPER FUNCTIONS FOR DISASSEMBLY ####
##########################################

def get_base_addr(input_path):
    base_addr = None
    baddr_match = re.search(re.compile("0x(?P<base_addr>[0-9a-fA-F]{8,16})$"), input_path)
    if baddr_match:
        base_addr = int(baddr_match.group("base_addr"), 16)
    return base_addr


def get_input_files(filepath):
    input_data = []
    with open(filepath, "r") as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=",")
        for index, row in enumerate(csv_reader):
            if len(row) == 3:
                family = row[0]
                version = row[1]
                filepath = row[2]
                input_data.append((filepath, family, version))
    return input_data


def readFileContent(file_path):
    file_content = b""
    with open(file_path, "rb") as fin:
        file_content = fin.read()
    return file_content


def disassemble(file_info):
    filepath, family, version = file_info
    disassembler = Disassembler()
    if get_base_addr(filepath) is not None:
        base_addr = get_base_addr(filepath)
        smda_report = disassembler.disassembleBuffer(readFileContent(filepath), base_addr)
        smda_report.filename = os.path.basename(filepath)
    else:
        smda_report = disassembler.disassembleFile(filepath)
    smda_report.family = family
    smda_report.version = version
    return smda_report

###############################
#### PRODUCE RESULT MATRIX ####
###############################

def score_to_color(score):
    if score >= 90:
        return "0080ff"  # dark blue
    elif score >= 80:
        return "00ffff"  # cyan
    elif score >= 70:
        return "00ff00"  # green 
    elif score >= 60:
        return "c0ff00"  # lime
    elif score >= 50:
        return "ffff00"  # yellow
    elif score >= 40:
        return "ffc000"  # orange
    elif score >= 30:
        return "ff8000"  # dark orange
    elif score >= 20:
        return "ff4000"  # red-orange
    elif score >= 10:
        return "ff0000"  # red
    elif score > 0:
        return "444444"  # light grey
    else:
        return "222222"  # dark grey / background

def produce_cross_crompare(data_path, output_path, method=None, custom_sequence=None, cluster_sequence=False):
    """ Generate a n:n cross comparision of all reports provided

    Args:
        data_path: the path to the folder containing reports of samples to be compared
        output_path: where to stored the rendered reports
        method: which similarity percentage to use ("unweighted", "score_weighted", "frequency_weighted")
        custom_sequence: use this order of sample_ids
        cluster_sequence: use hierarchical clustering to automatically determine a sequence
    """
    if method is None:
        method = "unweighted"
    sample_id_to_info = {}
    sample_id_to_matches = {}
    total_time_matching = 0
    sample_sequence = []
    # load all reports
    for filename in sorted(os.listdir(data_path)):
        report_path = os.path.abspath(data_path + os.sep + filename)
        report = {}
        with open(report_path, "r") as fjson:
            report = json.load(fjson)
            report = report["data"]
        if report:
            sample_id = report["info"]["sample"]["sample_id"]
            sample_sequence.append(sample_id)
            sample_id_to_info[sample_id] = report["info"]["sample"]
            sample_id_to_matches[sample_id] = report["matches"]["samples"]
            total_time_matching += report["info"]["job"]["duration"]
    # in case we have no custom reordering, use simple incremented orderering
    if custom_sequence is not None:
        sample_sequence = custom_sequence
        print("Using custom sample sequence:")
        print(sample_sequence)
    sample_id_set = set(sample_sequence)
    matching_percent = {i: {j: 0 for j in sample_sequence} for i in sample_sequence}
    matching_matches = {i: {j: 0 for j in sample_sequence} for i in sample_sequence}
    for sample_id, matches in sorted(sample_id_to_matches.items()):
        for matched_sample in matches:
            other_sample_id = matched_sample["sample_id"]
            if other_sample_id in sample_id_set:
                matching_percent[sample_id][other_sample_id] = matched_sample["matched"]["percent"][method]
                matching_matches[sample_id][other_sample_id] = matched_sample["matched"]["functions"]["combined"]
        matching_percent[sample_id][sample_id] = 100
    # if desired, optimize ordering of the matrix by using clustering
    if not custom_sequence and cluster_sequence:
        clustered_sequence = calculate_clustered_sequence(matching_percent)
        sample_sequence = [index for index in reversed(clustered_sequence)]
        print("Used clustering to calculate sample sequence:")
        print(sample_sequence)
    box_size = 15
    output_html = open(os.path.join(os.path.dirname(__file__), "header.html"), "r").read()
    output_html += f"<p>Cross Comparison of all {len(sample_sequence)} samples in the data set ({int(len(sample_sequence) * (len(sample_sequence)-1) / 2)} unique pairs).</p>"
    output_html += f"<p>Total matching took {total_time_matching:5.2f} seconds, with an average of {total_time_matching/len(sample_id_to_info):5.2f} seconds.</p>"
    output_html += "<table>\n"
    output_html += "<tr>"
    output_html += f'<td style="font-size: {box_size-2}px;color: #eeeeee">#</td>\n'
    output_html += f'<td style="font-size: {box_size-2}px;color: #eeeeee">SHA256</td>\n'
    output_html += f'<td style="font-size: {box_size-2}px;color: #eeeeee">family</td>\n'
    output_html += f'<td style="font-size: {box_size-2}px;color: #eeeeee">version</td>\n'
    output_html += f'<td style="font-size: {box_size-2}px;color: #eeeeee">Bit</td>\n'
    output_html += f'<td style="font-size: {box_size-2}px;color: #eeeeee">FNs</td>\n'
    output_html += (
        f'<td style="font-size: {box_size-2}px;color: #eeeeee" colspan="{len(sample_sequence)}">Matrix</td>\n'
    )
    output_html += "</tr>"
    for sample_id in sample_sequence:
        sha256 = sample_id_to_info[sample_id]["sha256"] if sample_id in sample_id_to_info else "0" * 64
        bitness = sample_id_to_info[sample_id]["bitness"]
        family = sample_id_to_info[sample_id]["family"]
        version = sample_id_to_info[sample_id]["version"]
        num_functions = sample_id_to_info[sample_id]["statistics"]["num_functions"]
        output_html += "<tr>"
        output_html += f'<td style="font-size: {box_size-2}px;color: #eeeeee">{sample_id}</td>\n'
        output_html += f'<td style="font-size: {box_size-2}px;color: #ffff00">{sha256[:8]}</td>\n'
        output_html += f'<td style="font-size: {box_size-2}px">{family}</td>\n'
        output_html += f'<td style="font-size: {box_size-2}px">{version}</td>\n'
        output_html += f'<td style="font-size: {box_size-2}px">{bitness}</td>\n'
        output_html += f'<td style="font-size: {box_size-2}px;color: #ffff00">{num_functions}</td>\n'
        for other_sample_id in sample_sequence:
            family_b = sample_id_to_info[other_sample_id]["family"]
            version_b = sample_id_to_info[other_sample_id]["version"]
            percent = matching_percent[sample_id][other_sample_id]
            num_matches = matching_matches[sample_id][other_sample_id]
            sample_a_funcs = (
                sample_id_to_info[sample_id]["statistics"]["num_functions"] if sample_id in sample_id_to_info else 0
            )
            sample_b_funcs = (
                sample_id_to_info[other_sample_id]["statistics"]["num_functions"]
                if other_sample_id in sample_id_to_info
                else 0
            )
            sample_a_sha256 = sample_id_to_info[sample_id]["sha256"] if sample_id in sample_id_to_info else 0
            sample_b_sha256 = (
                sample_id_to_info[other_sample_id]["sha256"] if other_sample_id in sample_id_to_info else 0
            )
            match_color = score_to_color(percent)
            output_html += f'<td><span class="hint--top" data-hint="MCRIT: {percent} ({num_matches} matches) &#10;'
            output_html += f"{sample_id}: {sample_a_sha256[:8]} -- {family} {version} -- ({sample_a_funcs} func)"
            output_html += "&#10;vs.&#10;"
            output_html += (
                f'{other_sample_id}: {sample_b_sha256[:8]} -- {family} {version} -- ({sample_b_funcs} func)" '
            )
            cell_content = f'<a href="../one_to_one_reports/matches_{sample_id}_{other_sample_id}.txt" target="_blank">&nbsp;</a>' if sample_id != other_sample_id else '&nbsp;'
            output_html += f' style="background-color: #{match_color}; width: {box_size}px; height: {box_size}px; ">{cell_content}</span></td>\n'
        output_html += f"</tr>\n"
    output_html += "</table>\n</body></html>"
    with open(f"{output_path}/report_{method}.html", "w") as fout:
        fout.write(output_html)

#######################################
#### PRODUCE ALL 1:1 MATCH REPORTS ####
#######################################

def export_one_to_one(data_path, output_path, sample_ids, function_id_to_data):
    print("finally exporting all individual 1:1 reports...")
    sample_id_to_info = {}
    sample_id_to_matches = {}
    total_time_matching = 0
    # load all reports
    for filename in os.listdir(data_path):
        report_path = os.path.abspath(data_path + os.sep + filename)
        report = {}
        with open(report_path, "r") as fjson:
            report = json.load(fjson)
            report = report["data"]
        if report:
            sample_id = report["info"]["sample"]["sample_id"]
            sample_id_to_info[sample_id] = report["info"]["sample"]
            sample_id_to_matches[sample_id] = report["matches"]["functions"]
            total_time_matching += report["info"]["job"]["duration"]
    for sample_id, matches in sorted(sample_id_to_matches.items()):
        matches_per_sample = _aggregateMatchesPerSample(matches)
        for foreign_sample_id, function_matches in matches_per_sample.items():
            if foreign_sample_id not in sample_ids:
                continue
            function_matches = {int(k): v for k, v in function_matches.items()}
            with open(f"{output_path}/matches_{sample_id}_{foreign_sample_id}.txt", "w") as f_out:
                f_out.write("function_id_a,offset_a,name_a,size_a,function_id_b,offset_b,name_b,size_b,type_score,is_library\n")
                for function_id, foreign_matches in sorted(function_matches.items()):
                    by_foreign_function_id = defaultdict(list)
                    for foreign_match in foreign_matches:
                        by_foreign_function_id[foreign_match[2]].append(foreign_match)
                    for foreign_function_id, individual_matches in by_foreign_function_id.items():
                        match_score = max([m[1] for m in individual_matches])
                        match_type = "pichash" if "pichash" in [m[0] for m in individual_matches] else "minhash"
                        is_library_match = any([m[3] for m in individual_matches])
                        fa_id = function_id
                        fa_off = "0x%08x" % function_id_to_data[function_id]["offset"]
                        fa_name = function_id_to_data[function_id]["function_name"]
                        fa_ins = function_id_to_data[function_id]["num_instructions"]
                        fb_id = foreign_function_id
                        fb_off = "0x%08x" % function_id_to_data[foreign_function_id]["offset"]
                        fb_name = function_id_to_data[foreign_function_id]["function_name"]
                        fb_ins = function_id_to_data[foreign_function_id]["num_instructions"]
                        match_entry = (fa_id, fa_off, fa_name, fa_ins, fb_id, fb_off, fb_name, fb_ins, match_type, match_score)
                        f_out.write(f"{fa_id},{fa_off},{fa_name},{fa_ins},{fb_id},{fb_off},{fb_name},{fb_ins},{match_type},{match_score},{is_library_match}\n")



def main(argv):
    argparser = argparse.ArgumentParser(
        description="Disassemble binaries and send to MCRIT index, then compare all against each other and produce matching matrix."
    )
    argparser.add_argument(
        "-o", "--output_path", type=str, default=None, help="Path to store the raw matching data and reports (default: ./reports)."
    )
    argparser.add_argument(
        "-m", "--mcrit_server", type=str, default="http://127.0.0.1:8000", help="MCRIT server address."
    )
    argparser.add_argument(
        "-c",
        "--clustering",
        action="store_true",
        default=False,
        help="Use hierachical clustering to optimize grouping in the output matrix.",
    )
    argparser.add_argument(
        "input_path", type=str, default="", help="Path for the input specification file (csv: filepath,family,version)."
    )
    if len(argv) < 2:
        argparser.print_usage()
        return 1

    ARGS = argparser.parse_args()
    if not ARGS.output_path:
        output_path = os.path.join(os.path.dirname(__file__), "reports")
        print(f"No output folder set, clearing and using: {output_path}")
        try:
            shutil.rmtree(output_path)
        except FileNotFoundError:
            print("Output folder did not exist before.")
        print("Creating new reports folder...")
        ensure_dir(output_path)
    else:
        output_path = ARGS.output_path
    # prepare output path
    smda_path = output_path + "/smda_reports"
    match_path = output_path + "/match_data"
    report_path = output_path + "/match_reports"
    one_to_one_path = output_path + "/one_to_one_reports"
    ensure_dir(smda_path)
    ensure_dir(match_path)
    ensure_dir(report_path)
    ensure_dir(one_to_one_path)
    clear_dir(match_path)
    clear_dir(report_path)
    clear_dir(one_to_one_path)

    client = McritClient(mcrit_server=ARGS.mcrit_server)

    if ARGS.input_path and os.path.isfile(ARGS.input_path):
        # load input description
        input_files = get_input_files(ARGS.input_path)
        # disassemble and index files
        jobs = []
        sample_ids = []
        for file_info in tqdm.tqdm(input_files, desc="DISASSEMBLING & UPLOADING", total=len(input_files)):
            # load cached data if available
            sample_filename = os.path.basename(file_info[0])
            if sample_filename + ".smda" in os.listdir(smda_path):
                smda_report = SmdaReport.fromFile(f"{smda_path}/{sample_filename}.smda")
                smda_json = smda_report.toDict()
                print(smda_report)
            else:
                smda_report = disassemble(file_info)
                print(smda_report)
                smda_json = smda_report.toDict()
                with open(f"{smda_path}/{smda_report.filename}.smda", "w") as fout:
                    json.dump(smda_json, fout, indent=1, sort_keys=True)
            sample_entry, job_id = client.addReport(smda_report)
            sample_ids.append(sample_entry.sample_id)
            jobs.append(job_id)
        # before we can match, we must wait for the minhashing:
        for job_id in tqdm.tqdm(jobs, desc="WAITING FOR MINHASHER"):
            client.awaitResult(job_id)
        # schedule matching jobs
        jobs = []
        for sample_id in sample_ids:
            job_id = client.requestMatchesForSample(sample_id)
            jobs.append((sample_id, job_id))
        # pull matching data
        for (sample_id, job_id) in tqdm.tqdm(jobs, desc="WAITING FOR MATCHING RESULTS"):
            matching_data = client.awaitResult(job_id)
            # store data - this will refresh our cache in case we had to recalculate
            with open(f"{match_path}/sample_{sample_id}.json", "w") as fout:
                json.dump(matching_data, fout, indent=1, sort_keys=True)
        # potentially define a custom sequence (list of int), sample_ids
        custom_sequence = None
        if not ARGS.clustering:
            custom_sequence = sample_ids
        # aggregate and produce output
        for matching_method in MATCHING_METHODS:
            # TODO from here on, this should be updated to reflect new MatchingResult objects.
            raise NotImplemented("Not updated to new result objects")
            produce_cross_crompare(
                match_path, 
                report_path, 
                method=matching_method,
                custom_sequence=custom_sequence, 
                cluster_sequence=ARGS.clustering
            )
        # pull function_id mapping
        function_id_to_data = get_function_data_mapping(client, sample_ids)
        # run again to produce all 1:1 reports
        export_one_to_one(match_path, one_to_one_path, sample_ids, function_id_to_data)
    else:
        argparser.print_help()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
