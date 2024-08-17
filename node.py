import matplotlib.pyplot as plt
import networkx as nx

# Create a graph
G = nx.Graph()
G.add_nodes_from([1, 2, 3, 4])
G.add_edges_from([(1, 2), (2, 3), (3, 4), (4, 1)])

# Draw the graph
pos = nx.spring_layout(G)
nx.draw(G, pos, with_labels=True, node_size=1000, node_color='skyblue', font_size=12, font_weight='bold')

# Add interactive functionality
def on_node_click(event):
    if event.inaxes is not None:
        for node in G.nodes:
            if (event.xdata - pos[node][0])**2 + (event.ydata - pos[node][1])**2 < 0.01:
                print(f'Clicked node: {node}')
                # You can add your custom logic here for node click actions

plt.gcf().canvas.mpl_connect('button_press_event', on_node_click)

plt.show()
