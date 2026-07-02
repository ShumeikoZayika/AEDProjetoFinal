#ifndef SERVICE_H
#define SERVICE_H

#include <string>
#include <vector>
#include <map>
#include <utility>
#include "graph.h"
#include "database.h"
#include "algorithms.h"

// ---------------------------------------------------------------------------
// Service layer (Nível 4)
//
// Separates the application logic from any interface (local menu, API, GUI).
// Every operation validates its input and returns a clear ok/error status,
// so the same logic can back a console menu, a REST API or a graphical UI.
// The algorithms invoked here are the ones implemented in Nível 3.
// ---------------------------------------------------------------------------

// Generic result of an operation that may fail.
struct OpResult {
    bool ok = false;
    std::string message;   // human-readable success or error message
    static OpResult success(const std::string& m) { return { true,  m }; }
    static OpResult error(const std::string& m)   { return { false, m }; }
};

class Service {
public:
    // `db` is optional; when provided, save()/load() persist the graph.
    explicit Service(Graph& g, Database* db = nullptr) : g_(g), db_(db) {}

    // ---- CRUD operations ----------------------------------------------
    OpResult createNode(const std::string& id, const std::string& label,
                        const std::string& typeStr);
    OpResult createEdge(const std::string& srcId, const std::string& tgtId,
                        const std::string& relationStr);
    OpResult deleteNode(const std::string& id);
    OpResult deleteEdge(const std::string& srcId, const std::string& tgtId,
                        const std::string& relationStr);
    const Node* getNode(const std::string& id) const;          // nullptr if absent
    std::vector<const Node*> listNodesByType(const std::string& typeStr,
                                             bool& validType) const;

    // ---- Graph queries / algorithms (Nível 3) -------------------------
    // dirStr: "out" (default), "in" or "both"
    OpResult neighbours(const std::string& id, const std::string& dirStr,
                        std::vector<const Node*>& out) const;
    OpResult shortestPath(const std::string& srcId, const std::string& dstId,
                          std::vector<std::string>& path) const;
    std::vector<std::pair<std::string, double>> ranking() const;            // PageRank
    std::vector<Algorithms::DegreeCentrality> degreeRanking() const;        // degree

    // ---- Statistics ---------------------------------------------------
    struct Stats {
        int nodes = 0;
        int edges = 0;
        std::map<std::string, int> nodesByType;   // type -> count
        std::string topByPageRank;
        std::string topByDegree;
    };
    Stats stats() const;

    // ---- Persistence --------------------------------------------------
    OpResult save();
    OpResult reload();

private:
    Graph& g_;
    Database* db_;
};

#endif
