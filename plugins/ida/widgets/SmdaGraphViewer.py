# -----------------------------------------------------------------------
# This is an example illustrating how to use the user graphing functionality
# in Python
# (c) Hex-Rays
# adopted for rendering GraphDiffing in MCRIT

import idaapi


from smda.common.SmdaFunction import SmdaFunction
from smda.common.SmdaReport import SmdaReport
from smda.common.BinaryInfo import BinaryInfo

from idaapi import *


class GraphCloser(action_handler_t):
    def __init__(self, graph):
        action_handler_t.__init__(self)
        self.graph = graph

    def activate(self, ctx):
        self.graph.Close()

    def update(self, ctx):
        return AST_ENABLE_ALWAYS
        
        
class SmdaGraphViewer(GraphViewer):

    def __init__(self, parent, sample_entry, function_entry, smda_function: SmdaFunction, coloring):
        self.title = "No Function"
        if smda_function is not None:
            self.title = f"CFG for sample {sample_entry.sample_id} ({sample_entry.family}); function: {function_entry.function_id}@0x{smda_function.offset:x}"
        GraphViewer.__init__(self, self.title)
        self.parent = parent
        self.name = "SmdaGraphViewer"
        self.smda_function = smda_function
        self._offset_to_node_id = {}
        self._node_id_to_offset = {}
        self._offset_to_color = coloring

    def draw(self):
        if self.smda_function is None:
            return
        self._offset_to_node_id = {}
        for block in self.smda_function.getBlocks():
            node_id = self.AddNode(block.offset)
            self._offset_to_node_id[block.offset] = node_id
            self._node_id_to_offset[node_id] = block.offset
            self.OnGetText(node_id)
        for src, dests in self.smda_function.blockrefs.items():
            for dest in dests:
                src_id = self._offset_to_node_id[src]
                dest_id = self._offset_to_node_id[dest]
                self.AddEdge(src_id, dest_id)

    def OnRefresh(self):
        self.Clear()
        self._offset_to_node_id = {}
        self._node_id_to_offset = {}
        self.draw()
        return True

    def OnGetText(self, node_id):
        """ Render a rendered BB as single, multi-line string """
        # TODO: if there is EVER a way to influence color of text in GraphViewer, use it to increase contrast...
        if self.smda_function is None:
            return
        block_offset = self._node_id_to_offset[node_id]
        rendered_ins = []
        if block_offset in self.smda_function.blocks:
            for smda_ins in self.smda_function.blocks[block_offset]:
                printable_api = ""
                apiref_str = self.smda_function.apirefs.get(smda_ins.offset, "")
                if apiref_str:
                    printable_api = f"[{apiref_str}]"
                if printable_api:
                    rendered_ins.append(f'{smda_ins.offset:x}: {smda_ins.mnemonic} {printable_api}')
                else:
                    rendered_ins.append(f'{smda_ins.offset:x}: {smda_ins.mnemonic} {smda_ins.operands}')
        if self._node_id_to_offset[node_id] in self._offset_to_color:
            # IDA uses BBGGRR instead of RRGGBB
            remapped_color = (
                (self._offset_to_color[self._node_id_to_offset[node_id]] // (256*256)) + 
                (self._offset_to_color[self._node_id_to_offset[node_id]] & 0x00FF00) + 
                ((self._offset_to_color[self._node_id_to_offset[node_id]] & 0x0000FF) * 256*256)
            )
            return ("\n".join(rendered_ins), remapped_color)
        else:
            return ("\n".join(rendered_ins))


    def OnHint(self, node_id):
        if self.smda_function is None:
            return
        # TODO use this properly
        return "0x%x %s" % (self._node_id_to_offset[node_id], "some text")

    def Show(self):
        if not GraphViewer.Show(self):
            return False
        actname = "graph_closer:%s" % self.title
        register_action(action_desc_t(actname, "Close %s" % self.title, GraphCloser(self)))
        # attach_action_to_popup(self.GetTCustomControl(), None, actname)
        return True

        
def show_example():
    smda_report = SmdaReport.fromFile("0e967868c1f693097857d6d1069a3efca1e50f4516bb2637a10761d9bf4992ff_unpacked.smda")
    g = SmdaGraphViewer(smda_report.getFunction(0x40D77A))
    if g.Show():
        return g
    else:
        return None


if __name__ == "__main__":
    g = show_example()
    if g:
        print("Graph created and displayed!")
