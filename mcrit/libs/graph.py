from collections import defaultdict

class Graph:
    # straightforward implementation to enable us to do DFS to find clusters in undirected graphs
    # credit: Neelam Yadav
    # https://www.geeksforgeeks.org/depth-first-search-or-dfs-for-a-graph/
    def __init__(self):
        self.graph = defaultdict(list)

    def addNode(self, v):
        self.graph[v].append(v)

    def addEdge(self, u, v):
        self.graph[u].append(v)

    def DFSUtil(self, v, visited):
        visited.add(v)
        for neighbour in self.graph[v]:
            if neighbour not in visited:
                self.DFSUtil(neighbour, visited)

    def DFS(self, v):
        visited = set()
        self.DFSUtil(v, visited)
        return visited
