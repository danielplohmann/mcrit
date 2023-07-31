import struct
import hashlib
import logging 

from rapidfuzz.distance import Levenshtein
from smda.intel.IntelInstructionEscaper import IntelInstructionEscaper



class FunctionCfgMatcher(object):

    def __init__(self, sample_entry_a, smda_function_a, sample_entry_b, smda_function_b) -> None:
        """
        Initialize with two smda_functions and their respective sample_entries or smda_reports (only needed for base_addr and binary_size)
        """
        self.sample_entry_a = sample_entry_a
        self.sample_entry_b = sample_entry_b
        self.smda_function_a = smda_function_a
        self.smda_function_b = smda_function_b
        self.match_colors = {
            # based on hashing
            "regular_pic": "#00DDFF",
            "small_pic": "#C0F4FF",
            "escaped": "#00ff00",
            # based on distance function
            0: "#40ff40",
            1: "#c0ff80",
            2: "#FFFF40",
            3: "#FFCC40",
            99: "#FFA0A0",
        }

    @staticmethod
    def getPicBlockHashesForFunction(sample_entry, smda_function, min_size=0):
        pic_block_hashes = []
        for block in smda_function.getBlocks():
            if block.length >= min_size:
                escaped_binary_seq = []
                for instruction in block.getInstructions():
                    escaped_binary_seq.append(instruction.getEscapedBinary(IntelInstructionEscaper, escape_intraprocedural_jumps=True, lower_addr=sample_entry.base_addr, upper_addr=sample_entry.base_addr + sample_entry.binary_size))
                as_bytes = bytes([ord(c) for c in "".join(escaped_binary_seq)])
                hashed = struct.unpack("Q", hashlib.sha256(as_bytes).digest()[:8])[0]
                pic_block_hashes.append({"offset": block.offset, "hash": hashed, "size": block.length})
        return pic_block_hashes

    def getAllPicblockMatches(self):
        node_colors = {"a": {}, "b": {}}
        all_phbs_a = []
        for block in self.smda_function_a.getBlocks():
            escaped_binary_seq = []
            for instruction in block.getInstructions():
                escaped_binary_seq.append(instruction.getEscapedBinary(IntelInstructionEscaper, escape_intraprocedural_jumps=True, lower_addr=self.sample_entry_a.base_addr, upper_addr=self.sample_entry_a.base_addr + self.sample_entry_a.binary_size))
            as_bytes = bytes([ord(c) for c in "".join(escaped_binary_seq)])
            hashed = struct.unpack("Q", hashlib.sha256(as_bytes).digest()[:8])[0]
            all_phbs_a.append({"offset": block.offset, "hash": hashed, "size": block.length})
        all_phbs_b = []
        for block in self.smda_function_b.getBlocks():
            escaped_binary_seq = []
            for instruction in block.getInstructions():
                escaped_binary_seq.append(instruction.getEscapedBinary(IntelInstructionEscaper, escape_intraprocedural_jumps=True, lower_addr=self.sample_entry_b.base_addr, upper_addr=self.sample_entry_b.base_addr + self.sample_entry_b.binary_size))
            as_bytes = bytes([ord(c) for c in "".join(escaped_binary_seq)])
            hashed = struct.unpack("Q", hashlib.sha256(as_bytes).digest()[:8])[0]
            all_phbs_b.append({"offset": block.offset, "hash": hashed, "size": block.length})
        phb_a = set([pbh["hash"] for pbh in all_phbs_a])
        phb_b = set([pbh["hash"] for pbh in all_phbs_b])
        phb_match_addr_a = [(pbh["offset"], pbh["size"]) for pbh in all_phbs_a if pbh["hash"] in phb_a.intersection(phb_b)]
        phb_match_addr_b = [(pbh["offset"], pbh["size"]) for pbh in all_phbs_b if pbh["hash"] in phb_a.intersection(phb_b)]
        for addr, size in phb_match_addr_a:
            if size >= 4:
                node_colors["a"][f"Node0x{addr:x}"] = self.match_colors["regular_pic"]
            else:
                node_colors["a"][f"Node0x{addr:x}"] = self.match_colors["small_pic"]
        for addr, size in phb_match_addr_b:
            if size >= 4:
                node_colors["b"][f"Node0x{addr:x}"] = self.match_colors["regular_pic"]
            else:
                node_colors["b"][f"Node0x{addr:x}"] = self.match_colors["small_pic"]
        return node_colors

    def getEscapedMatches(self):
        node_colors = {"a": {}, "b": {}}
        all_escapes_a = []
        for block in self.smda_function_a.getBlocks():
            escaped_ins_seq = []
            for instruction in block.getInstructions():
                escaped_ins = IntelInstructionEscaper.escapeMnemonic(instruction.mnemonic) + " " + IntelInstructionEscaper.escapeOperands(instruction)
                escaped_ins_seq.append(escaped_ins)
            merged = ";".join(escaped_ins_seq)
            # print("0x%x" % block.offset, merged)
            hashed = struct.unpack("Q", hashlib.sha256(merged.encode("ascii")).digest()[:8])[0]
            all_escapes_a.append({"offset": block.offset, "hash": hashed})
        all_escapes_b = []
        for block in self.smda_function_b.getBlocks():
            escaped_ins_seq = []
            for instruction in block.getInstructions():
                escaped_ins = IntelInstructionEscaper.escapeMnemonic(instruction.mnemonic) + " " + IntelInstructionEscaper.escapeOperands(instruction)
                escaped_ins_seq.append(escaped_ins)
            merged = ";".join(escaped_ins_seq)
            # print("0x%x" % block.offset, merged)
            hashed = struct.unpack("Q", hashlib.sha256(merged.encode("ascii")).digest()[:8])[0]
            all_escapes_b.append({"offset": block.offset, "hash": hashed})
        phb_a = set([pbh["hash"] for pbh in all_escapes_a])
        phb_b = set([pbh["hash"] for pbh in all_escapes_b])
        phb_match_addr_a = [pbh["offset"] for pbh in all_escapes_a if pbh["hash"] in phb_a.intersection(phb_b)]
        phb_match_addr_b = [pbh["offset"] for pbh in all_escapes_b if pbh["hash"] in phb_a.intersection(phb_b)]
        for addr in phb_match_addr_a:
            node_colors["a"][f"Node0x{addr:x}"] = self.match_colors["escaped"]
        for addr in phb_match_addr_b:
            node_colors["b"][f"Node0x{addr:x}"] = self.match_colors["escaped"]
        return node_colors

    def getLevenshteinMatches(self, unmatched_nodes):
        node_colors = {"a": {}, "b": {}}
        # across all blocks in unmatched nodes, collect tokens and map to symbols
        # token -> symbol, like "M REG, REG" -> 0
        # we use symbols from chr(0x20) to chr(0x7e), i.e. up to 94 printables, which "should always be enough (TM)""
        alphabet = {}
        num_symbols = 0
        # offset -> symbolified block
        candidate_blocks_a = {}
        for block in self.smda_function_a.getBlocks():
            if block.offset not in unmatched_nodes["a"]:
                continue
            symbolified_block = ""
            for instruction in block.getInstructions():
                escaped_ins = instruction.mnemonic + " " + IntelInstructionEscaper.escapeOperands(instruction)
                if escaped_ins not in alphabet:
                    alphabet[escaped_ins] = chr(0x30 + num_symbols)
                    num_symbols += 1
                    if num_symbols > 94:
                        raise Exception("Basic Block contains too many tokens to compare.")
                symbolified_block += alphabet[escaped_ins]
            candidate_blocks_a[block.offset] = symbolified_block
        candidate_blocks_b = {}
        for block in self.smda_function_b.getBlocks():
            if block.offset not in unmatched_nodes["b"]:
                continue
            symbolified_block = ""
            for instruction in block.getInstructions():
                escaped_ins = instruction.mnemonic + " " + IntelInstructionEscaper.escapeOperands(instruction)
                if escaped_ins not in alphabet:
                    alphabet[escaped_ins] = chr(0x30 + num_symbols)
                    num_symbols += 1
                    if num_symbols > 94:
                        raise Exception("Basic Block contains too many tokens to compare.")
                symbolified_block += alphabet[escaped_ins]
            candidate_blocks_b[block.offset] = symbolified_block
        # print(alphabet)
        by_score = {0: [], 1: [], 2: [], 3: []}
        for block_a, symbols_a in candidate_blocks_a.items():
            for block_b, symbols_b in candidate_blocks_b.items():
                distance = Levenshtein.distance(symbols_a, symbols_b, score_cutoff=3)
                if distance < 4:
                    by_score[distance].append((block_a, block_b))
                    # print(f"0x{block_a:x} 0x{block_b:x}: {symbols_a} || {symbols_b} - {distance}")
        used_blocks = set()
        for score, pairs in by_score.items():
            for pair in pairs:
                block_a, block_b = pair
                if block_a not in used_blocks and block_b not in used_blocks:
                    node_colors["a"][f"Node0x{block_a:x}"] = score
                    node_colors["b"][f"Node0x{block_b:x}"] = score
                    used_blocks.add(block_a)
                    used_blocks.add(block_b)
        node_colors["a"] = {k: self.match_colors[v] for k, v in node_colors["a"].items()}
        node_colors["b"] = {k: self.match_colors[v] for k, v in node_colors["b"].items()}
        return node_colors

    def getColoredMatches(self):
        # thresholded edit distance match over escaped instruction sequence: green to orange
        node_colors = {"a": {}, "b": {}}
        # no match / base color: bleak red
        for block in self.smda_function_a.getBlocks():
            node_colors["a"][f"Node0x{block.offset:x}"] = self.match_colors[99]
        for block in self.smda_function_b.getBlocks():
            node_colors["b"][f"Node0x{block.offset:x}"] = self.match_colors[99]
        # escaped blocks matches
        escaped_block_matches = self.getEscapedMatches()
        node_colors["a"].update(escaped_block_matches["a"])
        node_colors["b"].update(escaped_block_matches["b"])
        # ad-hoc picblock match (small BB): bleak teal
        # full picblock match (regular BB>=4 instructions): teal
        smaller_picblock_matches = self.getAllPicblockMatches()
        node_colors["a"].update(smaller_picblock_matches["a"])
        node_colors["b"].update(smaller_picblock_matches["b"])
        # compare everything not colored by now using our adapted Levenshtein
        unmatched_nodes = {
            "a": [int(k[6:], 16) for k, v in node_colors["a"].items() if v == self.match_colors[99]], 
            "b": [int(k[6:], 16) for k, v in node_colors["b"].items() if v == self.match_colors[99]], 
        }
        levenshtein_matches = self.getLevenshteinMatches(unmatched_nodes)
        node_colors["a"].update(levenshtein_matches["a"])
        node_colors["b"].update(levenshtein_matches["b"])
        return node_colors
