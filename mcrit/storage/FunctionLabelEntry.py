import datetime
from typing import TYPE_CHECKING, Dict, Optional


class FunctionLabelEntry(object):
    # MCRIT specific
    function_id: int
    function_label: str
    username: str
    timestamp: datetime

    def __init__(
        self,
        function_label: str,
        username: str,
        function_id: Optional[int]=None,
        timestamp: Optional[datetime.datetime]=None
    ) -> None:
        self.function_label = function_label
        self.username = username
        self.function_id = function_id
        self.timestamp = timestamp
        if timestamp is None:
            self.timestamp = datetime.datetime.utcnow()

    def setFunctionId(self, function_id):
        self.function_id = function_id

    def toDict(self):
        function_entry = {
            "function_label": self.function_label,
            "username": self.username,
            "timestamp": self.timestamp.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        return function_entry

    @classmethod
    def fromDict(cls, entry_dict):
        function_label_entry = cls(None, None)  # type: ignore
        function_label_entry.function_label = entry_dict["function_label"]
        # function_entry.function_id = entry_dict["function_id"]
        function_label_entry.username = entry_dict["username"]
        function_label_entry.function_id = entry_dict["function_id"] if "function_id" in entry_dict else None
        function_label_entry.timestamp = datetime.datetime.strptime(entry_dict["timestamp"], "%Y-%m-%dT%H:%M:%S")
        return function_label_entry

    def __str__(self):
        return f"FunctionLabel: '{self.function_label}' -- by user: {self.username}"
