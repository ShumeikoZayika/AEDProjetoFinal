#ifndef GRAPH_H
#define GRAPH_H

#include <string>
#include <vector>
#include <map>
#include "node.h"
#include "edge.h"

// Direction used by neighbour/edge queries.
//   OUT  -> relations leaving the node   (outgoing / adjacency list)
//   IN   -> relations arriving at node   (incoming / inverse adjacency list)
//   BOTH -> union of the two
enum class Direction { OUT, IN, BOTH };

class Graph {
public:
    // Add a node; returns false if id already exists
    bool addNode(const Node& node);

    // Add a directed edge with relation-type validation; returns false on error
    bool addEdge(const std::string& srcId, const std::string& tgtId,
                 RelationType relation, const std::string& desc = "");

    // Retrieve a node by id (returns nullptr if not found)
    const Node* getNode(const std::string& id) const;

    // List neighbours of a node in a given direction.
    // OUT  = nodes this node points to            (default, backwards compatible)
    // IN   = nodes that point to this node
    // BOTH = both sets, de-duplicated by id
    std::vector<const Node*> getNeighbours(const std::string& id,
                                           Direction dir = Direction::OUT) const;

    // Convenience: incoming neighbours (nodes that point to `id`)
    std::vector<const Node*> getInNeighbours(const std::string& id) const;

    // List all edges originating from a node (outgoing adjacency list)
    std::vector<const Edge*> getOutEdges(const std::string& id) const;

    // List all edges arriving at a node (inverse / incoming adjacency list)
    std::vector<const Edge*> getInEdges(const std::string& id) const;

    // Degree helpers (structural analysis)
    int outDegree(const std::string& id) const;  // number of outgoing relations
    int inDegree(const std::string& id) const;   // number of incoming relations
    int degree(const std::string& id) const;     // in + out

    // List all nodes of a given entity type
    std::vector<const Node*> getNodesByType(EntityType type) const;

    // Print the entire graph to stdout
    void print() const;

    // Basic statistics
    int nodeCount() const { return (int)nodes_.size(); }
    int edgeCount() const { return (int)allEdges_.size(); }

    // Iteration helpers (used by Database and exporters)
    std::vector<const Node*> getAllNodes() const;
    std::vector<const Edge*> getAllEdges() const;

    // Remove all nodes and edges (used before loadGraph)
    void clear();

    // Set a property on an existing node (used when loading from DB)
    bool setNodeProperty(const std::string& nodeId,
                         const std::string& key,
                         const std::string& value);

    // Remove a node and every edge incident to it (outgoing and incoming).
    // Returns false if the node does not exist.
    bool removeNode(const std::string& id);

    // Remove a specific directed edge (source --relation--> target).
    // Returns false if no matching edge exists.
    bool removeEdge(const std::string& srcId, const std::string& tgtId,
                    RelationType relation);

private:
    std::map<std::string, Node> nodes_;              // id -> Node
    std::map<std::string, std::vector<Edge>> adj_;   // id -> outgoing edges
    std::map<std::string, std::vector<Edge>> adjIn_; // id -> incoming edges (inverse)
    std::vector<Edge> allEdges_;                     // flat list of all edges
};

#endif
