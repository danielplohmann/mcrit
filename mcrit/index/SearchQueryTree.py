from typing import Literal

class SearchTermNode:
    value: str

    def __init__(self, value):
        self.value = value

class SearchConditionNode:
    field: str
    operator: Literal["", "=", "<", "<=", ">", ">="]
    value: str

    def __init__(self, field, operator, value):
        self.field = field 
        self.operator = operator 
        self.value = value

