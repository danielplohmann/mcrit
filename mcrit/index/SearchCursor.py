import base64
import json
from typing import Any, List, Optional

from mcrit.index.SearchQueryTree import AndNode, OrNode, SearchConditionNode


class MinimalSearchCursor:
    """
    Contains the minimum amount of data (when combined with search order info) required to reconstruct a FullSearchCursor.
    """
    record_values: List[Any]
    is_forward_search: bool

    def __init__(self):
        self.record_values = []
        self.is_forward_search = True

    def toDict(self):
        result = self.record_values, 1 if self.is_forward_search else 0
        return result

    @classmethod 
    def fromDict(cls, data):
        result = cls()
        result.record_values, result.is_forward_search = data[0], bool(data[1])
        return result

    def toStr(self):
        return base64.urlsafe_b64encode(json.dumps(self.toDict()).encode()).decode()
        # return json.dumps(self.toDict())

    @classmethod 
    def fromStr(cls, data):
        # return cls.fromDict(json.loads(data))
        if data is not None:
            return cls.fromDict(json.loads(base64.urlsafe_b64decode(data).decode()))


class FullSearchCursor:
    """
    Contains Data to deliver sorted search results after a certain point.
    sort_fields:
        is the list of n fields used for sorting.
        Fields with higher sorting priority come first.
        These fields together should be unique for each db entry.
    sort_directions:
        a list of n booleans corresponding to the n fields.
        True means ascending order, False descending
    record_values: 
        the n concrete field values of a record.
        The SearchCursor references those records within the db
        which come either after or before this record.
        This record itself
    is_forward_search:
        if True, the SearchCursor references records after the specified record.
        if False, the SearchCursor references records befor the specified record.
    is_initial_cursor:
        True if record_values contains no meaningful data and the cursor should not exclude any records 
    """
    sort_fields: List[str]
    sort_directions: List[bool]
    record_values: List[Any]
    is_forward_search: bool
    is_initial_cursor: bool

    def __init__(self, input_cursor: Optional[MinimalSearchCursor], sort_by_list):
        """
        sort_by_list:
            a list of (sort_field, sort_direction) entries    
        """
        self.sort_fields = [sort_info[0] for sort_info in sort_by_list]
        self.sort_directions = [sort_info[1] for sort_info in sort_by_list]
        if input_cursor is not None:
            self.record_values = input_cursor.record_values
            self.is_forward_search = input_cursor.is_forward_search
            self.is_initial_cursor = False
        else:
            self.record_values = []
            self.is_forward_search = True
            self.is_initial_cursor = True

    @property
    def sort_by_list(self):
        return zip(self.sort_fields, self.sort_directions)
    
    def toTree(self):
        def get_operator(i):
            direction = self.sort_directions[i] ^ (not self.is_forward_search)
            return ">" if direction else "<"

        if self.is_initial_cursor:
            return AndNode([])

        # condition has form (a > a0) or (a = a0 and b>b0) or (a=a0 and b=b0 and c>c0)...
        conditions = []
        for inner_condition_length in range(1, len(self.sort_fields)+1):
            inner_condition = []
            for i in range(inner_condition_length):
                if i != inner_condition_length-1:
                    operator = "="
                else:
                    operator = get_operator(i)
                inner_condition.append(SearchConditionNode(self.sort_fields[i], operator, self.record_values[i]))
            conditions.append(AndNode(inner_condition))

        return OrNode(conditions)


