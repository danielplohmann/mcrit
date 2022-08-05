from typing import List, Literal, Union

class Node:
    pass

NodeType = Union["SearchTermNode", "SearchConditionNode", "NotNode", "AndNode", "OrNode"]

class _ListNode(Node):
    children: List[NodeType]
    _name = ""

    def __init__(self, children:List[NodeType], flatten=True):
        self.children = children
        if flatten:
            self.flatten()

    def flatten(self):
        flattened_children = []
        for child in self.children:
            if isinstance(child, type(self)):
                flattened_children.extend(child.children)
            else:
                flattened_children.append(child)
        self.children = flattened_children

    def __repr__(self) -> str:
        children_str = ", ".join([str(child) for child in self.children])
        return f"{self._name}({children_str})"

class AndNode(_ListNode):
    _name = "And"

class OrNode(_ListNode):
    _name = "Or"

class NotNode(Node):
    child: NodeType 

    def __init__(self, child:NodeType):
        self.child = child

    def __repr__(self) -> str:
        return f"Not({str(self.child)})"

class SearchTermNode(Node):
    value: str

    def __init__(self, value):
        self.value = value

    def __repr__(self) -> str:
        return f"Search('{self.value}')"

class SearchConditionNode(Node):
    field: str
    operator: Literal["", "=", "<", "<=", ">", ">=", "!=", "?", "!?"]
    value: str

    def __init__(self, field, operator, value):
        self.field = field 
        self.operator = operator 
        self.value = value

    def __repr__(self) -> str:
        if self.operator != "":
            operator_str = self.operator
        else:
            operator_str = ":"
        return f"Condition('{self.field}' {operator_str} '{self.value}')"

class BaseVisitor:
    def visit(self, node:NodeType):
        if isinstance(node, SearchTermNode):
            return self.visitSearchTermNode(node)
        if isinstance(node, SearchConditionNode):
            return self.visitSearchConditionNode(node)
        if isinstance(node, AndNode):
            return self.visitAndNode(node)
        if isinstance(node, OrNode):
            return self.visitOrNode(node)
        if isinstance(node, NotNode):
            return self.visitNotNode(node)

    # Or
    def _visitOrChild(self, node:NodeType):
        return self.visit(node)
    
    def _visitOrDone(self, children):
        return OrNode(children)

    def visitOrNode(self, node:OrNode):
        return self._visitOrDone([self._visitOrChild(child) for child in node.children])

    # And
    def _visitAndChild(self, node:NodeType):
        return self.visit(node)
    
    def _visitAndDone(self, children):
        return AndNode(children)

    def visitAndNode(self, node:AndNode):
        return self._visitAndDone([self._visitAndChild(child) for child in node.children])

    # Not
    def _visitNotChild(self, node:NodeType):
        return self.visit(node)
    
    def _visitNotDone(self, child):
        return NotNode(child)

    def visitNotNode(self, node:NotNode):
        return self._visitNotDone(self._visitNotChild(node.child))

    # Leaf Nodes
    def visitSearchTermNode(self, node:SearchTermNode):
        return node

    def visitSearchConditionNode(self, node:SearchConditionNode):
        return node

class SearchFieldResolver(BaseVisitor):
    def __init__(self, *search_fields) -> None:
        super().__init__()
        self.search_fields = search_fields

    def visitSearchTermNode(self, node: SearchTermNode):
        children = []
        for field in self.search_fields:
            children.append(
                SearchConditionNode(field, "?", node.value)
            )
        return OrNode(children)

class FilterSingleElementLists(BaseVisitor):
    def _visitAndDone(self, children):
        if len(children) == 1:
            return children[0]
        return AndNode(children)

    def _visitOrDone(self, children):
        if len(children) == 1:
            return children[0]
        return OrNode(children)

class Negate(BaseVisitor):
    def visitSearchTermNode(self, node: SearchTermNode):
        raise NotImplementedError
    
    def visitSearchConditionNode(self, node: SearchConditionNode):
        reverse_op_dict = {
            "": "!=",
            "=": "!=",
            "<": ">=",
            "<=": ">",
            ">": "<=",
            ">=": "<",
            "!=": "=",
            "?": "!?",
            "!?": "?",
        }
        return SearchConditionNode(node.field, reverse_op_dict[node.operator], node.value)

    def _visitAndDone(self, children):
        return OrNode(children)

    def _visitOrDone(self, children):
        return AndNode(children)

    def visitNotNode(self, node:NotNode):
        return PropagateNot().visit(node.child)
        

class PropagateNot(BaseVisitor):
    def visitNotNode(self, node:NotNode):
        return Negate().visit(node.child)
