from mcrit.storage.SampleEntry import SampleEntry


class HtmlRenderer(object):
    def __init__(self, index):
        self._index = index
        return

    def renderAggregatedMatchingReport(self, aggregated_report):
        sample_entry = SampleEntry.fromDict(aggregated_report["sample_info"])
        match_summary = aggregated_report["aggregation"]
        table_body = "<tr><th>sample_id</th><th>family</th><th>version</th><th>bitness</th><th>SHA256</th><th>minhash</th><th>pichash</th><th>combined</th><th>library</th><th>bytescore</th><th>percent</th><th>vs</th></tr>\n"
        for _, entry in sorted(match_summary.items(), key=lambda x: x[1]["percent"], reverse=True):
            table_body += "<tr>"
            table_body += "<td>%d</td>" % entry["sample_id"]
            table_body += "<td>%s</td>" % entry["family"]
            table_body += "<td>%s</td>" % entry["version"]
            table_body += "<td>%s</td>" % entry["bitness"]
            table_body += "<td>%s</td>" % entry["sha256"]
            table_body += "<td>%d</td>" % entry["minhash_matches"]
            table_body += "<td>%d</td>" % entry["pichash_matches"]
            table_body += "<td>%d</td>" % entry["combined_matches"]
            table_body += "<td>%d</td>" % entry["library_matches"]
            table_body += "<td>%5.2f</td>" % entry["bytescore"]
            table_body += "<td>%5.2f</td>" % entry["percent"]
            table_body += f"<td><a href=\"{entry['sample_id']}/html\">AxB</a> <a href=\"../../{entry['sample_id']}/matches/{sample_entry.sample_id}/html\">BxA</a></td>"
            table_body += "</tr>\n"
        query_summary = f"sample_id: {sample_entry.sample_id} ({sample_entry.sha256}) - family: {sample_entry.family} / version: {sample_entry.version}"
        html_report = """
<html>
<head>
<style>
table, tr, td, th {border: 1px solid black;}
</style>
</head>
<body>
<p>
  query: %s
</p>
<table>
%s
</table>
<p>query time: %5.2fs</p>
</body>
""" % (
            query_summary,
            table_body,
            aggregated_report["duration"],
        )
        return html_report

    def _getFunctionInfos(self, function_ids):
        infos = {}
        for fid in function_ids:
            infos[fid] = self._index._storage.getFunctionById(fid)
        return infos

    def renderMatchingVsReport(self, matching_report, best_only=False):
        sample_a = SampleEntry.fromDict(matching_report["sample_info"])
        sample_b = SampleEntry.fromDict(matching_report["other_sample_info"])
        duration = matching_report["duration"]

        query_summary_a = f"sample_id: {sample_a.sample_id} ({sample_a.sha256}) - family: {sample_a.family} / version: {sample_a.version}"
        query_summary_b = f"sample_id: {sample_b.sample_id} ({sample_b.sha256}) - family: {sample_b.family} / version: {sample_b.version}"

        sample_a_binweight = sample_a.binweight
        pichash_matched_functions = matching_report["pichash"]["pichash_summary"]["num_own_functions_matched"]
        pichash_matched_bytes = matching_report["pichash"]["pichash_summary"]["bytes_matched"]
        pichash_summary = f"PicHash: {pichash_matched_functions} functions, {pichash_matched_bytes} bytes ({100.0*pichash_matched_bytes/sample_a_binweight:5.2f})%"

        minhash_matched_functions = matching_report["minhash"]["minhash_summary"]["num_own_functions_matched"]
        minhash_matched_bytes = matching_report["minhash"]["minhash_summary"]["bytes_matched"]
        minhash_summary = f"MinHash: {minhash_matched_functions} functions, {minhash_matched_bytes} bytes ({100.0*minhash_matched_bytes/sample_a_binweight:5.2f})%"

        function_ids = set()
        summarized_results = {}
        for fid, function_matches in matching_report["pichash"]["pichash_matches"].items():
            function_ids.add(int(fid))
            func_a = summarized_results.get(fid, {})
            for sample_id, matches in function_matches["matches"].items():
                function_ids.update([entry[0] for entry in matches])
                for match in matches:
                    func_b = func_a.get(match[0], [])
                    func_b.append(("pichash", 100.0))
                    func_a[match[0]] = func_b
            summarized_results[fid] = func_a
        for fid, function_matches in matching_report["minhash"]["minhash_matches"].items():
            function_ids.add(int(fid))
            func_a = summarized_results.get(fid, {})
            for sample_id, matches in function_matches["matches"].items():
                function_ids.update([entry[0] for entry in matches])
                for match in matches:
                    func_b = func_a.get(match[0], [])
                    func_b.append(("minhash", match[1]))
                    func_a[match[0]] = func_b
            summarized_results[fid] = func_a
        table_body = ""
        function_infos = self._getFunctionInfos(function_ids)
        table_body = ""
        table_body += f"<tr>"
        table_body += f"<th>match id</th>"
        table_body += f"<th>function id a</th>"
        table_body += f"<th>offset a</th>"
        table_body += f"<th>name a</th>"
        table_body += f"<th>function id b</th>"
        table_body += f"<th>offset b</th>"
        table_body += f"<th>name b</th>"
        table_body += f"<th>size a</th>"
        table_body += f"<th>size b</th>"
        table_body += f"<th>match type</th>"
        table_body += f"<th>match score</th>"
        table_body += f"</tr>\n"
        num_matches = 1
        for fid_a, a_data in sorted(summarized_results.items()):
            for fid_b, b_data in sorted(a_data.items(), key=lambda x: max(x[1]), reverse=True):
                for entry in sorted(b_data, reverse=True):
                    table_body += f"<tr>"
                    table_body += f"<td>{num_matches}</td>"
                    table_body += f"<td>{fid_a}</td>"
                    table_body += f"<td>0x{function_infos[fid_a].offset:08x}</td>"
                    table_body += f"<td>{function_infos[fid_a].function_name}</td>"
                    table_body += f"<td>{fid_b}</td>"
                    table_body += f"<td>0x{function_infos[fid_b].offset:08x}</td>"
                    table_body += f"<td>{function_infos[fid_b].function_name}</td>"
                    table_body += f"<td>{function_infos[fid_a].binweight}</td>"
                    table_body += f"<td>{function_infos[fid_b].binweight}</td>"
                    table_body += f"<td>{entry[0]}</td>"
                    table_body += f"<td>{entry[1]}</td>"
                    table_body += f"</tr>\n"
                    num_matches += 1
                    if entry[0] == "pichash":
                        break
                if best_only:
                    break

        header = "<html>\n<head>\n<style>\ntable, tr, td, th {border: 1px solid black;}\n</style>\n</head>\n<body>\n"
        body_info = f"<p>\nquery:<br />\n{query_summary_a}<br />\nvs.<br />\n{query_summary_b}</p>"
        body_overview = f"<p>\nsummary:<br />\n{pichash_summary}<br />\n{minhash_summary}</p>"
        body_table = f"<table>\n{table_body}\n</table>\n<p>query time: {duration:5.2f}s</p>"
        footer = "</body>\n</html>"
        return header + body_info + body_overview + body_table + footer
