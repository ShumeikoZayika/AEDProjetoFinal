#ifndef GUI_H
#define GUI_H

#include "graph.h"
#include "service.h"

// ---------------------------------------------------------------------------
// Native desktop GUI (Nível 5) — raylib
//
// Opens an interactive window that draws the knowledge graph. All quantitative
// inputs are computed by the C++ engine:
//   - node radius -> PageRank (Algorithms::pageRank)
//   - node info   -> degree centrality (Graph::inDegree / outDegree)
//   - highlighted path -> shortest path computed by the C++ BFS
// Interaction: drag nodes, left-click to inspect a node and its neighbours,
// right-click a second node to draw the BFS path, toggle entity types.
// ---------------------------------------------------------------------------
namespace Gui {
    // Blocks until the window is closed.
    // `svc` exposes the create/save/reload operations to the interface;
    // `g` is the graph being visualised (mutated through `svc`).
    void run(Service& svc, Graph& g);
}

#endif
