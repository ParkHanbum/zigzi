import pydotplus

"""
digraph G {
    node[shape=record]
    loc_0x1000 [
        label="{{loc_1000|mov eax, eax} |
        {loc_1005|xor eax, eax} |
        {loc_100A|lea eax, [eax]} |
        {loc_100B|call loc_1050}} "];
    loc_0x1040 [
        label="{{loc_1040|mov eax, eax} |
        {<loc_0x1050>loc_1050|xor eax, eax} |
        {loc_100A|lea eax, [eax]} |
        {loc_100B|call loc_1050}}"];

	loc_0x1000 -> loc_0x1040:loc_0x1050
}
"""

dot = pydotplus.graphviz.Dot(prog='test', format='dot')
node = pydotplus.graphviz.Node(name='node', shape='record')
dot.add_node(node)
dot.add_node(pydotplus.graphviz.Node(name='loc_0x1000', label='{{loc_1000|mov eax, eax} | \
        {loc_1005|xor eax, eax} | \
        {loc_100A|lea eax, [eax]} | \
        {loc_100B|call loc_1050}}'))

dot.add_node(pydotplus.graphviz.Node(name='loc_0x1040', label='{{loc_1040|mov eax, eax} | \
        {<loc_0x1050>loc_1050|xor eax, eax} | \
        {loc_105A|lea eax, [eax]} | \
        {loc_105B|call loc_1050}}'))

dot.add_edge(pydotplus.graphviz.Edge(src='loc_0x1000', dst='loc_0x1040:loc_0x1050'))
#dot.add_subgraph(graph)

dot.write('C:\\work\\test')
dot.write_gif('C:\\work\\test.gif')
