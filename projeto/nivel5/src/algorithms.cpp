#include <queue>
#include <stack>
#include <set>
#include <algorithm>
#include <cmath>
#include <cctype>
#include "algorithms.h"

namespace Algorithms {

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// Build an adjacency list (id -> sorted list of neighbour ids).
// directed = true  : only outgoing edges (src -> tgt)
// directed = false : edges added in both directions
static std::map<std::string, std::vector<std::string>>
buildAdjacency(const Graph& g, bool directed) {
    std::map<std::string, std::vector<std::string>> adj;

    // ensure every node has an entry (even isolated ones)
    for (const Node* n : g.getAllNodes())
        adj[n->id];

    for (const Edge* e : g.getAllEdges()) {
        adj[e->sourceId].push_back(e->targetId);
        if (!directed)
            adj[e->targetId].push_back(e->sourceId);
    }

    // sort + dedup for deterministic traversal order
    for (auto& kv : adj) {
        std::sort(kv.second.begin(), kv.second.end());
        kv.second.erase(std::unique(kv.second.begin(), kv.second.end()),
                        kv.second.end());
    }
    return adj;
}

// Normalise a name into a comparison key: lowercase, keep only alphanumerics.
static std::string normalise(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s)
        if (std::isalnum(c))
            out.push_back((char)std::tolower(c));
    return out;
}

// Collect the normalised name variants of a node: id, alias property,
// and each part of a "A / B" style label.
static std::vector<std::string> nameVariants(const Node& n) {
    std::vector<std::string> variants;

    auto pushIfNotEmpty = [&](const std::string& raw) {
        std::string k = normalise(raw);
        if (!k.empty()) variants.push_back(k);
    };

    pushIfNotEmpty(n.id);
    pushIfNotEmpty(n.label);

    // split label on '/' to capture aliases embedded in the label
    std::string part;
    for (char c : n.label) {
        if (c == '/') { pushIfNotEmpty(part); part.clear(); }
        else          { part.push_back(c); }
    }
    pushIfNotEmpty(part);

    // explicit alias property
    auto it = n.properties.find("alias");
    if (it != n.properties.end())
        pushIfNotEmpty(it->second);

    std::sort(variants.begin(), variants.end());
    variants.erase(std::unique(variants.begin(), variants.end()), variants.end());
    return variants;
}

// ---------------------------------------------------------------------------
// Traversals
// ---------------------------------------------------------------------------

std::vector<std::string> bfs(const Graph& g, const std::string& start, bool directed) {
    std::vector<std::string> order;
    if (!g.getNode(start)) return order;

    auto adj = buildAdjacency(g, directed);
    std::set<std::string> visited;
    std::queue<std::string> q;

    q.push(start);
    visited.insert(start);

    while (!q.empty()) {
        std::string cur = q.front(); q.pop();
        order.push_back(cur);
        for (const std::string& nb : adj[cur]) {
            if (!visited.count(nb)) {
                visited.insert(nb);
                q.push(nb);
            }
        }
    }
    return order;
}

std::vector<std::string> dfs(const Graph& g, const std::string& start, bool directed) {
    std::vector<std::string> order;
    if (!g.getNode(start)) return order;

    auto adj = buildAdjacency(g, directed);
    std::set<std::string> visited;
    std::stack<std::string> st;

    st.push(start);
    while (!st.empty()) {
        std::string cur = st.top(); st.pop();
        if (visited.count(cur)) continue;
        visited.insert(cur);
        order.push_back(cur);

        // push neighbours in reverse sorted order so that the smallest
        // id is processed first (matches recursive DFS over sorted edges)
        const auto& nbs = adj[cur];
        for (auto it = nbs.rbegin(); it != nbs.rend(); ++it)
            if (!visited.count(*it))
                st.push(*it);
    }
    return order;
}

// ---------------------------------------------------------------------------
// Shortest path (BFS over unweighted graph)
// ---------------------------------------------------------------------------

std::vector<std::string> shortestPath(const Graph& g, const std::string& src,
                                      const std::string& dst, bool directed) {
    std::vector<std::string> path;
    if (!g.getNode(src) || !g.getNode(dst)) return path;
    if (src == dst) { path.push_back(src); return path; }

    auto adj = buildAdjacency(g, directed);
    std::map<std::string, std::string> parent;
    std::set<std::string> visited;
    std::queue<std::string> q;

    q.push(src);
    visited.insert(src);

    bool found = false;
    while (!q.empty() && !found) {
        std::string cur = q.front(); q.pop();
        for (const std::string& nb : adj[cur]) {
            if (!visited.count(nb)) {
                visited.insert(nb);
                parent[nb] = cur;
                if (nb == dst) { found = true; break; }
                q.push(nb);
            }
        }
    }

    if (!found) return path;  // empty: unreachable

    // reconstruct path dst -> src then reverse
    std::string node = dst;
    while (node != src) {
        path.push_back(node);
        node = parent[node];
    }
    path.push_back(src);
    std::reverse(path.begin(), path.end());
    return path;
}

// ---------------------------------------------------------------------------
// Degree centrality
// ---------------------------------------------------------------------------

std::vector<DegreeCentrality> degreeCentrality(const Graph& g) {
    std::vector<DegreeCentrality> result;
    for (const Node* n : g.getAllNodes()) {
        DegreeCentrality dc;
        dc.id    = n->id;
        dc.in    = g.inDegree(n->id);
        dc.out   = g.outDegree(n->id);
        dc.total = dc.in + dc.out;
        result.push_back(dc);
    }
    // sort by total degree desc, ties broken by id asc (deterministic ranking)
    std::sort(result.begin(), result.end(),
              [](const DegreeCentrality& a, const DegreeCentrality& b) {
                  if (a.total != b.total) return a.total > b.total;
                  return a.id < b.id;
              });
    return result;
}

// ---------------------------------------------------------------------------
// PageRank
// ---------------------------------------------------------------------------

std::map<std::string, double> pageRank(const Graph& g, double damping,
                                       int maxIterations, double tol) {
    std::map<std::string, double> rank;

    std::vector<const Node*> nodes = g.getAllNodes();
    const int N = (int)nodes.size();
    if (N == 0) return rank;

    // out-degree and incoming-link lists
    std::map<std::string, int> outDeg;
    std::map<std::string, std::vector<std::string>> inLinks;
    for (const Node* n : nodes) { outDeg[n->id] = 0; inLinks[n->id]; }

    for (const Edge* e : g.getAllEdges()) {
        outDeg[e->sourceId]++;
        inLinks[e->targetId].push_back(e->sourceId);
    }

    // initial uniform distribution
    const double init = 1.0 / N;
    for (const Node* n : nodes) rank[n->id] = init;

    const double base = (1.0 - damping) / N;

    for (int iter = 0; iter < maxIterations; ++iter) {
        // mass held by dangling nodes (no outgoing edges)
        double danglingSum = 0.0;
        for (const Node* n : nodes)
            if (outDeg[n->id] == 0)
                danglingSum += rank[n->id];

        std::map<std::string, double> next;
        double diff = 0.0;

        for (const Node* n : nodes) {
            double incoming = 0.0;
            for (const std::string& u : inLinks[n->id])
                incoming += rank[u] / outDeg[u];

            double val = base + damping * (danglingSum / N + incoming);
            next[n->id] = val;
            diff += std::fabs(val - rank[n->id]);
        }

        rank.swap(next);
        if (diff < tol) break;  // converged
    }

    return rank;
}

std::vector<std::pair<std::string, double>>
rankEntities(const Graph& g, double damping, int maxIterations, double tol) {
    auto rank = pageRank(g, damping, maxIterations, tol);

    std::vector<std::pair<std::string, double>> ranked(rank.begin(), rank.end());
    std::sort(ranked.begin(), ranked.end(),
              [](const std::pair<std::string, double>& a,
                 const std::pair<std::string, double>& b) {
                  if (a.second != b.second) return a.second > b.second;
                  return a.first < b.first;  // deterministic tie-break
              });
    return ranked;
}

// ---------------------------------------------------------------------------
// Entity resolution
// ---------------------------------------------------------------------------

std::vector<std::string> resolveByName(const Graph& g, const std::string& name) {
    std::vector<std::string> hits;
    std::string key = normalise(name);
    if (key.empty()) return hits;

    for (const Node* n : g.getAllNodes()) {
        auto variants = nameVariants(*n);
        if (std::find(variants.begin(), variants.end(), key) != variants.end())
            hits.push_back(n->id);
    }
    std::sort(hits.begin(), hits.end());
    return hits;
}

std::vector<std::vector<std::string>> findPotentialDuplicates(const Graph& g) {
    // map normalised variant -> set of node ids sharing it
    std::map<std::string, std::set<std::string>> byVariant;

    for (const Node* n : g.getAllNodes())
        for (const std::string& v : nameVariants(*n))
            byVariant[v].insert(n->id);

    // collect groups of >= 2 distinct ids; merge groups that overlap
    // (a node may share different variants with different nodes)
    std::map<std::string, std::set<std::string>> groups; // representative -> members
    std::map<std::string, std::string> repOf;

    auto findRep = [&](const std::string& id) -> std::string {
        std::string r = id;
        while (repOf.count(r) && repOf[r] != r) r = repOf[r];
        return r;
    };

    for (const auto& kv : byVariant) {
        const std::set<std::string>& ids = kv.second;
        if (ids.size() < 2) continue;
        // union all ids in this variant under one representative
        std::string rep = findRep(*ids.begin());
        for (const std::string& id : ids) {
            if (!repOf.count(id)) repOf[id] = id;
            std::string r2 = findRep(id);
            repOf[r2] = rep;
        }
    }

    // rebuild groups from representatives
    for (const auto& kv : byVariant) {
        if (kv.second.size() < 2) continue;
        for (const std::string& id : kv.second)
            groups[findRep(id)].insert(id);
    }

    std::vector<std::vector<std::string>> result;
    for (const auto& kv : groups) {
        if (kv.second.size() < 2) continue;
        result.emplace_back(kv.second.begin(), kv.second.end());
    }
    std::sort(result.begin(), result.end());
    return result;
}

// ---------------------------------------------------------------------------
// Analytical queries
// ---------------------------------------------------------------------------

std::vector<std::string> actorsUsingMalware(const Graph& g,
                                            const std::string& malwareId) {
    std::vector<std::string> actors;
    for (const Edge* e : g.getAllEdges()) {
        if (e->relation == RelationType::USES && e->targetId == malwareId) {
            const Node* src = g.getNode(e->sourceId);
            if (src && src->type == EntityType::THREAT_ACTOR)
                actors.push_back(src->id);
        }
    }
    std::sort(actors.begin(), actors.end());
    actors.erase(std::unique(actors.begin(), actors.end()), actors.end());
    return actors;
}

std::vector<std::string> indicatorsForThreat(const Graph& g,
                                             const std::string& threatId) {
    std::vector<std::string> indicators;
    for (const Edge* e : g.getAllEdges()) {
        if (e->relation == RelationType::INDICATES && e->targetId == threatId) {
            const Node* src = g.getNode(e->sourceId);
            if (src && src->type == EntityType::INDICATOR)
                indicators.push_back(src->id);
        }
    }
    std::sort(indicators.begin(), indicators.end());
    indicators.erase(std::unique(indicators.begin(), indicators.end()), indicators.end());
    return indicators;
}

// ---------------------------------------------------------------------------
// Most-probable inference
// ---------------------------------------------------------------------------

std::vector<ProbCandidate> mostProbable(const Graph& g,
                                        const std::string& fromId,
                                        EntityType type) {
    std::vector<ProbCandidate> result;
    if (!g.getNode(fromId)) return result;

    // BFS (não dirigido) para obter a distância do nó de partida a cada nó.
    auto adj = buildAdjacency(g, false);
    std::map<std::string, int> dist;
    std::queue<std::string> q;
    dist[fromId] = 0;
    q.push(fromId);
    while (!q.empty()) {
        std::string cur = q.front(); q.pop();
        for (const std::string& nb : adj[cur])
            if (!dist.count(nb)) { dist[nb] = dist[cur] + 1; q.push(nb); }
    }

    // PageRank para a componente "importância".
    auto pr = pageRank(g);

    for (const Node* n : g.getAllNodes()) {
        if (n->type != type) continue;
        if (n->id == fromId) continue;
        auto it = dist.find(n->id);
        if (it == dist.end()) continue;          // inalcançável
        int d = it->second; if (d < 1) d = 1;
        double p = pr.count(n->id) ? pr[n->id] : 0.0;
        result.push_back({ n->id, d, p, p / d });
    }

    std::sort(result.begin(), result.end(),
              [](const ProbCandidate& a, const ProbCandidate& b) {
                  if (a.score != b.score) return a.score > b.score;
                  if (a.distance != b.distance) return a.distance < b.distance;
                  return a.id < b.id;
              });
    return result;
}

} // namespace Algorithms
