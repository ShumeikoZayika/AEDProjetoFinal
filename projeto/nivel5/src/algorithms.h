#ifndef ALGORITHMS_H
#define ALGORITHMS_H

#include <string>
#include <vector>
#include <map>
#include <utility>
#include "graph.h"

// Analysis algorithms over the knowledge graph.
// All functions are read-only with respect to the graph.
namespace Algorithms {

    // ---- Traversals ----------------------------------------------------

    // Breadth-First Search starting from `start`.
    // Returns the visiting order (node ids). Empty if `start` does not exist.
    // directed = true follows only outgoing edges; false treats edges as bidirectional.
    std::vector<std::string> bfs(const Graph& g, const std::string& start,
                                 bool directed = true);

    // Depth-First Search starting from `start`.
    // Returns the visiting order (node ids). Empty if `start` does not exist.
    std::vector<std::string> dfs(const Graph& g, const std::string& start,
                                 bool directed = true);

    // ---- Shortest path -------------------------------------------------

    // Shortest path between two nodes (unweighted, via BFS).
    // Returns the sequence of node ids from src to dst (inclusive),
    // or an empty vector if no path exists.
    // CTI links are navigable in both directions, so default is undirected.
    std::vector<std::string> shortestPath(const Graph& g, const std::string& src,
                                          const std::string& dst, bool directed = false);

    // ---- Degree centrality ---------------------------------------------

    // Degree centrality of a node: incoming, outgoing and total relations.
    struct DegreeCentrality {
        std::string id;
        int in;     // incoming relations
        int out;    // outgoing relations
        int total;  // in + out
    };

    // Degree centrality for every node, sorted by total descending
    // (ties broken by id ascending) for ranking / visualisation.
    std::vector<DegreeCentrality> degreeCentrality(const Graph& g);

    // ---- PageRank ------------------------------------------------------

    // Classic PageRank over the directed graph.
    // Returns a map id -> score (scores sum to ~1.0).
    std::map<std::string, double> pageRank(const Graph& g, double damping = 0.85,
                                           int maxIterations = 100, double tol = 1e-9);

    // PageRank result sorted by score descending (ties broken by id ascending).
    std::vector<std::pair<std::string, double>>
        rankEntities(const Graph& g, double damping = 0.85,
                     int maxIterations = 100, double tol = 1e-9);

    // ---- Entity resolution ---------------------------------------------

    // Resolve a free-text name (e.g. "Cozy Bear") to the node ids it may refer to,
    // considering node id, label (incl. "A / B" forms) and the "alias" property.
    std::vector<std::string> resolveByName(const Graph& g, const std::string& name);

    // Scan the graph for groups of distinct nodes that likely represent the
    // same real-world entity (shared normalised name variant). Each inner
    // vector is a group of >= 2 node ids.
    std::vector<std::vector<std::string>> findPotentialDuplicates(const Graph& g);

    // ---- Analytical queries --------------------------------------------

    // "Que atores usam determinado malware?"
    // Returns threat-actor node ids that have a `uses` edge to malwareId.
    std::vector<std::string> actorsUsingMalware(const Graph& g,
                                                const std::string& malwareId);

    // "Que indicadores apontam para determinada ameaça?"
    // Returns indicator node ids that have an `indicates` edge to threatId.
    std::vector<std::string> indicatorsForThreat(const Graph& g,
                                                 const std::string& threatId);

    // ---- Most-probable inference ---------------------------------------

    // Candidate entity of a requested type, reachable from a start node.
    struct ProbCandidate {
        std::string id;
        int    distance;   // nº de relações até ao nó de partida (BFS, não dirigido)
        double pagerank;   // importância global
        double score;      // pagerank / distance  (mais perto + mais central => maior)
    };

    // "Qual a entidade mais provável do tipo `type` associada a `fromId`?"
    // Faz BFS (não dirigido) a partir de `fromId`, recolhe as entidades do tipo
    // pedido alcançáveis, e ordena-as por score = PageRank / distância
    // (desempate: distância menor, depois id). O primeiro elemento é o mais provável.
    std::vector<ProbCandidate> mostProbable(const Graph& g,
                                            const std::string& fromId,
                                            EntityType type);

} // namespace Algorithms

#endif
