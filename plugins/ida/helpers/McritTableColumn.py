# This file holds enums for configurable table column types across the different tables in the MCRIT plugin.
# The SHA256 hash of the sample, shortened to the first 8 hexbytes, right-click copies full hash to clipboard.
SHA256 = 1
# The name of the family assigned to the sample.
FAMILY_NAME = 1 << 1
# The version string assigned to the sample.
VERSION = 1 << 2
# Boolean indicating whether the sample is a library.
IS_LIBRARY = 1 << 3
# Unique identifier for the family as registered in MCRIT
FAMILY_ID = 1 << 4
# Unique identifier for the sample as registered in MCRIT
SAMPLE_ID = 1 << 5
# Unique identifier for the function as registered in MCRIT
FUNCTION_ID = 1 << 6
# The offset of the function or block within the sample.
OFFSET = 1 << 7
# The size of the function or block in bytes.
SIZE = 1 << 8
# The PIC block hash of the function or block.
PIC_BLOCK_HASH = 1 << 9
# The number of families matching the function or block.
FAMILIES = 1 << 10
# The number of samples matching the function or block.
SAMPLES = 1 << 11
# The number of functions matching the function or block.
FUNCTIONS = 1 << 12
# Boolean indicating whether there is a PIC hash match for the function or block
PIC_HASH_MATCH = 1 << 13
# Matching Score for the function
SCORE = 1 << 14
# The username of the user who submitted the label.
USER = 1 << 15
# The label assigned to the function
FUNCTION_LABEL = 1 << 16
# Timestamp of when the label was assigned
TIMESTAMP = 1 << 17
# ComboBox with all scores / labels for the function
SCORE_AND_LABEL = 1 << 18

MAP_COLUMN_TO_HEADER_STRING = {
    SHA256: "SHA256",
    FAMILY_NAME: "Family",
    VERSION: "Version",
    IS_LIBRARY: "Library?",
    FAMILY_ID: "Family ID",
    SAMPLE_ID: "Sample ID",
    FUNCTION_ID: "Function ID",
    OFFSET: "Offset",
    SIZE: "Size",
    PIC_BLOCK_HASH: "PIC#",
    FAMILIES: "Families",
    SAMPLES: "Samples",
    FUNCTIONS: "Functions",
    PIC_HASH_MATCH: "PIC?",
    SCORE: "Score",
    USER: "User",
    FUNCTION_LABEL: "Label",
    TIMESTAMP: "Timestamp",
    SCORE_AND_LABEL: "Score & Labels",
}

def columnTypeToIndex(column_type: int, configured_columns: list[int]) -> int | None:
    """
    Given a column type and a list of configured columns, return the index of the column type in the list.
    If the column type is not found, return None.
    """
    for index, ctype in enumerate(configured_columns):
        if ctype == column_type:
            return index
    return None
