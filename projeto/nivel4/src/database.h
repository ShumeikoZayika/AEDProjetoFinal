#ifndef DATABASE_H
#define DATABASE_H

#include <string>
#include <vector>
#include <sqlite3.h>
#include "graph.h"

class Database {
public:
    Database();
    ~Database();

    // Open (or create) the .db file and create the schema tables.
    // Returns true on success.
    bool initDB(const std::string& path);

    // Persist all nodes and edges from the graph into the database.
    // Existing rows with the same id are replaced.
    bool saveGraph(const Graph& g);

    // Reconstruct a graph from the database.
    // The graph is cleared before loading.
    bool loadGraph(Graph& g);

    // Search helpers — return copies, not pointers, because the Graph
    // that owns them might not exist yet.
    std::vector<Node> searchNodesByType(EntityType type);

    std::vector<Edge> searchEdgesBySource(const std::string& sourceId);
    std::vector<Edge> searchEdgesByTarget(const std::string& targetId);
    std::vector<Edge> searchEdgesByRelation(RelationType relation);

    bool isOpen() const { return db_ != nullptr; }

private:
    sqlite3* db_;

    // Execute a single SQL statement with no result rows.
    bool exec(const char* sql);

    // Low-level helpers
    bool createSchema();
    bool saveNode(const Node& node);
    bool saveEdge(const Edge& edge);

    // Read a Node from a prepared statement row (columns: id, label, type)
    Node nodeFromStmt(sqlite3_stmt* stmt);
    // Read an Edge from a prepared statement row (columns: source_id, target_id, relation, description)
    Edge edgeFromStmt(sqlite3_stmt* stmt);
};

#endif
