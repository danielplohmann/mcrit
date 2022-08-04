from typing import TYPE_CHECKING, Dict, Optional

from smda.common.BinaryInfo import BinaryInfo
from smda.common.SmdaFunction import SmdaFunction

from mcrit.minhash.MinHash import MinHash

if TYPE_CHECKING:  # pragma: no cover
    from mcrit.storage.SampleEntry import SampleEntry
    from smda.common.SmdaFunction import SmdaFunction

# Dataclass, post init
# constructor -> .fromSmdaFunction
# assume sample_entry, smda_function always available

# TODO remove (everywhere) from alchemy function


class FunctionEntry(object):
    # MCRIT specific
    function_id: int
    family_id: int
    sample_id: int
    minhash: bytes  # TODO rename -> minhash_bytes? minhash_hex?
    minhash_shingle_composition: Dict = None  # FIXME MongoDbStorage fails without this, ... why?
    # inherited from sample
    architecture: str
    # smda information
    function_name: str
    matches: Dict
    pichash: int
    picblockhashes: list
    num_blocks: int
    num_instructions: int
    binweight: float
    offset: int
    xcfg: Dict

    def __init__(
        self,
        sample_entry: "SampleEntry",
        smda_function: "SmdaFunction",
        function_id: int,
        minhash: Optional[MinHash] = None,
    ) -> None:
        self.function_id = function_id
        if sample_entry:
            self.family_id = sample_entry.family_id
            self.sample_id = sample_entry.sample_id
            self.architecture = sample_entry.architecture
        if smda_function:
            self.num_blocks = smda_function.num_blocks
            self.num_instructions = smda_function.num_instructions
            self.binweight = smda_function.binweight
            self.offset = smda_function.offset
            self.xcfg = smda_function.toDict()
            self.function_name = smda_function.function_name
            self.pichash = smda_function.pic_hash
            self.picblockhashes = []
        self.matches = {}
        empty_minhash = MinHash()
        self.minhash = minhash.getMinHash() if minhash else empty_minhash.getMinHash()
        self.shingler_composition = minhash.getComposition() if minhash else empty_minhash.getComposition()

    def getMinHash(self, minhash_bits=32):
        return MinHash(function_id=self.function_id, minhash_bytes=self.minhash, minhash_bits=minhash_bits)

    def toSmdaFunction(self):
        binary_info = BinaryInfo(b"")
        binary_info.architecture = self.architecture
        return SmdaFunction.fromDict(self.xcfg, binary_info=binary_info)

    def toDict(self):
        empty_minhash = MinHash()
        minhash = self.minhash if self.minhash else empty_minhash.getMinHash()
        shingler_composition = (
            self.minhash_shingle_composition if self.minhash_shingle_composition else empty_minhash.getComposition()
        )
        function_entry = {
            "architecture": self.architecture,
            "binweight": self.binweight,
            "family_id": self.family_id,
            "function_id": self.function_id,
            "function_name": self.function_name,
            "matches": self.matches,
            "minhash": minhash.hex(),
            "minhash_shingle_composition": shingler_composition,
            "num_blocks": self.num_blocks,
            "num_instructions": self.num_instructions,
            "offset": self.offset,
            "pichash": self.pichash,
            "picblockhashes": self.picblockhashes,
            "sample_id": self.sample_id,
            "xcfg": self.xcfg,
        }
        return function_entry

    @classmethod
    def fromDict(cls, entry_dict):
        function_entry = cls(None, None, entry_dict["function_id"])  # type: ignore
        function_entry.family_id = entry_dict["family_id"]
        # function_entry.function_id = entry_dict["function_id"]
        function_entry.sample_id = entry_dict["sample_id"]
        function_entry.architecture = entry_dict["architecture"]
        function_entry.function_name = entry_dict["function_name"]
        function_entry.matches = entry_dict["matches"]
        function_entry.pichash = entry_dict["pichash"]
        function_entry.picblockhashes = entry_dict["picblockhashes"]
        function_entry.minhash = bytes.fromhex(entry_dict["minhash"])
        function_entry.minhash_shingle_composition = entry_dict["minhash_shingle_composition"]
        function_entry.num_blocks = entry_dict["num_blocks"]
        function_entry.num_instructions = entry_dict["num_instructions"]
        function_entry.binweight = entry_dict["binweight"]
        function_entry.offset = entry_dict["offset"]
        function_entry.xcfg = entry_dict["xcfg"] if "xcfg" in entry_dict else None
        return function_entry

    @classmethod
    def fromAlchemyFunction(cls, function):
        function_entry = cls(None, None)  # type:ignore
        function_entry.binweight = function.binweight
        function_entry.function_id = function.id
        function_entry.family_id = function.family.id
        function_entry.sample_id = function.sample.id
        function_entry.architecture = function.architecture.name
        function_entry.function_name = function.function_name
        if function.pichash:
            function_entry.pichash = function.pichash.pichash
        if function.minhash:
            function_entry.minhash = function.minhash.minhash
        function_entry.num_blocks = function.num_blocks
        function_entry.num_instructions = function.num_instructions
        function_entry.offset = function.offset
        function_entry.xcfg = function.xcfg
        return function_entry

    def __str__(self):
        return "Family: {} Sample: {} Function: {} @ 0x{:08x} - {} blocks ({} hashes), {} instructions - pichash: {}".format(
            self.family_id,
            self.sample_id,
            self.function_id,
            self.offset,
            self.num_blocks,
            len(self.picblockhashes),
            self.num_instructions,
            self.pichash,
        )
