from functools import lru_cache
from string import whitespace
from pyparsing import (
    Word,
    CharsNotIn,
    CharsNotIn,
    Group,
    ZeroOrMore,
    OneOrMore,
    QuotedString,
    oneOf,
    Suppress,
    identchars,
    identbodychars,
    Forward,
    Keyword,
    StringEnd,
)

from mcrit.index.SearchQueryTree import AndNode, NodeType, NotNode, OrNode, SearchConditionNode, SearchTermNode

class SearchQueryParser:
    def __init__(self):
        self._methods = {
            "and": self._build_tree_and,
            "or": self._build_tree_or,
            "not": self._build_tree_not,
            "parenthesis": self._build_tree_parenthesis,
            "one_filter": self._build_tree_one_filter
        }
        self._parser = self._get_parser()
    
    def _get_parser(self):
        search_term = QuotedString('"', esc_char="\\", esc_quote='\\"') \
            | QuotedString("'", esc_char="\\", esc_quote="\\'") \
            | ZeroOrMore(Suppress(whitespace))+CharsNotIn(whitespace+"()")
        identifier = Word(identchars, identbodychars+".")
        operator = oneOf("< <= > >= = != ? !?")
        condition_compare = identifier + (":" + operator + search_term).leave_whitespace()
        condition_equal = identifier + (":" + search_term).leave_whitespace()
        one_filter = Group(condition_compare | condition_equal | search_term).setResultsName("one_filter")

        operatorOr = Forward()

        operatorParenthesis = (
            Group(Suppress("(") + operatorOr + Suppress(")")).setResultsName(
                "parenthesis"
            )
            | one_filter
        )

        operatorNot = Forward()
        operatorNot << (
            Group(Suppress(Keyword("NOT")) + operatorNot).setResultsName(
                "not"
            )
            | operatorParenthesis
        )

        operatorAnd = Forward()
        operatorAnd << (
            Group(
                operatorNot + Suppress(Keyword("AND")) + operatorAnd
            ).setResultsName("and")
            | Group(
                operatorNot + OneOrMore(~oneOf("AND OR") + operatorAnd)
            ).setResultsName("and")
            | operatorNot
        )

        operatorOr << (
            Group(
                operatorAnd + Suppress(Keyword("OR")) + operatorOr
            ).setResultsName("or")
            | operatorAnd
        )

        parser = operatorOr + StringEnd()
        return parser
    
    def _build_tree_or(self, argument) -> NodeType:
        assert len(argument) == 2
        children = [self._build_tree(child) for child in argument]
        return OrNode(children)

    def _build_tree_and(self, argument) -> NodeType:
        assert len(argument) == 2
        children = [self._build_tree(child) for child in argument]
        return AndNode(children)

    def _build_tree_parenthesis(self, argument) -> NodeType:
        assert len(argument) == 1
        return self._build_tree(argument[0])

    def _build_tree_not(self, argument) -> NodeType:
        assert len(argument) == 1
        return NotNode(self._build_tree(argument[0]))

    def _build_tree_one_filter(self, argument) -> NodeType:
        if len(argument) == 1:
            return SearchTermNode(argument[0])
        if len(argument) == 3:
            return SearchConditionNode(argument[0], "", argument[-1])
        if len(argument) == 4:
            return SearchConditionNode(argument[0], argument[-2], argument[-1])
        raise ValueError()
    
    def _build_tree(self, argument) -> NodeType:
        return self._methods[argument.getName()](argument)

    @lru_cache(maxsize=100)
    def parse(self, string:str) -> NodeType:
        if string.strip(whitespace) == "":
            return AndNode([])
        raw_result = self._parser.parse_string(string)
        assert len(raw_result) == 1
        result = self._build_tree(raw_result[0])
        return result