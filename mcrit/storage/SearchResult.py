from typing import Any, Dict, Generic, Iterator, List, Optional, Type, TypeVar

EntryT = TypeVar("EntryT")


class SearchResult(Generic[EntryT]):
    """What a search endpoint answers, with its entries deserialized (fkie-cad/mcritweb#64).

    The wire format of /search/{families,samples,functions} is a dict of dicts; the other
    accessors of McritClient hand out FamilyEntry/SampleEntry/FunctionEntry objects. This is
    the typed counterpart of that dict: `entries` maps the id to the entry, `id_match` is the
    entry a numeric search term named directly (or None), `sha_match` the sample a sha256
    search term named (samples only, or None), and `cursor` carries the two paging cursors
    as the endpoint returned them. toDict() gives the wire format back.
    """

    def __init__(self, entry_class: Type[EntryT]) -> None:
        self.entry_class = entry_class
        self.entries: Dict[int, EntryT] = {}
        self.cursor: Dict[str, Optional[str]] = {"forward": None, "backward": None}
        self.id_match: Optional[EntryT] = None
        self.sha_match: Optional[EntryT] = None
        # only the sample search answers a sha_match key; toDict() gives back what came in
        self._has_sha_match_key = False

    @classmethod
    def fromDict(cls, data: Dict[str, Any], entry_class: Type[EntryT]) -> "SearchResult[EntryT]":
        from_dict = getattr(entry_class, "fromDict")
        result = cls(entry_class)
        result.entries = {int(key): from_dict(value) for key, value in (data.get("search_results") or {}).items()}
        cursor = data.get("cursor") or {}
        result.cursor = {"forward": cursor.get("forward"), "backward": cursor.get("backward")}
        result.id_match = from_dict(data["id_match"]) if data.get("id_match") else None
        result.sha_match = from_dict(data["sha_match"]) if data.get("sha_match") else None
        result._has_sha_match_key = "sha_match" in data
        return result

    def toDict(self) -> Dict[str, Any]:
        """The wire format, as it arrives through the client: JSON object keys are strings."""
        data: Dict[str, Any] = {
            "search_results": {str(key): getattr(entry, "toDict")() for key, entry in self.entries.items()},
            "cursor": dict(self.cursor),
            "id_match": getattr(self.id_match, "toDict")() if self.id_match is not None else None,
        }
        if self._has_sha_match_key or self.sha_match is not None:
            data["sha_match"] = getattr(self.sha_match, "toDict")() if self.sha_match is not None else None
        return data

    @property
    def direct_matches(self) -> List[EntryT]:
        """The entries the search term named directly, by id or sha256, without duplicates."""
        matches = [match for match in (self.id_match, self.sha_match) if match is not None]
        return [match for index, match in enumerate(matches) if match not in matches[:index]]

    def __iter__(self) -> Iterator[EntryT]:
        return iter(self.entries.values())

    def __len__(self) -> int:
        return len(self.entries)

    def __repr__(self) -> str:
        return f"SearchResult({self.entry_class.__name__}, {len(self.entries)} entries, id_match={self.id_match is not None}, sha_match={self.sha_match is not None})"
