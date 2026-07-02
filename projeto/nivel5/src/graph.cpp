#include <cstdio>
#include <algorithm>
#include <set>
#include "graph.h"

bool Graph::addNode(const Node& node) {
    if (node.id.empty()) {
        printf("[ERRO] ID do nó não pode ser vazio.\n");
        return false;
    }
    if (nodes_.count(node.id)) {
        printf("[ERRO] Nó com id \"%s\" já existe.\n", node.id.c_str());
        return false;
    }
    if (node.type == EntityType::UNKNOWN) {
        printf("[ERRO] Tipo de entidade desconhecido para nó \"%s\".\n", node.id.c_str());
        return false;
    }
    nodes_[node.id] = node;
    adj_[node.id];     // ensure outgoing adjacency entry exists (even if empty)
    adjIn_[node.id];   // ensure incoming adjacency entry exists (even if empty)
    return true;
}

bool Graph::addEdge(const std::string& srcId, const std::string& tgtId,
                    RelationType relation, const std::string& desc) {
    if (!nodes_.count(srcId)) {
        printf("[ERRO] Nó de origem \"%s\" não existe.\n", srcId.c_str());
        return false;
    }
    if (!nodes_.count(tgtId)) {
        printf("[ERRO] Nó de destino \"%s\" não existe.\n", tgtId.c_str());
        return false;
    }
    if (relation == RelationType::UNKNOWN) {
        printf("[ERRO] Tipo de relação desconhecido entre \"%s\" e \"%s\".\n",
               srcId.c_str(), tgtId.c_str());
        return false;
    }

    EntityType srcType = nodes_.at(srcId).type;
    EntityType tgtType = nodes_.at(tgtId).type;

    if (!isValidRelation(srcType, relation, tgtType)) {
        printf("[ERRO] Relação inválida: %s --%s--> %s  (tipos: %s -> %s)\n",
               srcId.c_str(), relationTypeToString(relation).c_str(), tgtId.c_str(),
               entityTypeToString(srcType).c_str(), entityTypeToString(tgtType).c_str());
        return false;
    }

    Edge e(srcId, tgtId, relation, desc);
    adj_[srcId].push_back(e);    // outgoing adjacency list
    adjIn_[tgtId].push_back(e);  // inverse (incoming) adjacency list
    allEdges_.push_back(e);
    return true;
}

const Node* Graph::getNode(const std::string& id) const {
    auto it = nodes_.find(id);
    return (it != nodes_.end()) ? &it->second : nullptr;
}

std::vector<const Node*> Graph::getNeighbours(const std::string& id, Direction dir) const {
    std::vector<const Node*> result;
    std::set<std::string> seen;

    auto addFrom = [&](const std::map<std::string, std::vector<Edge>>& m, bool useTarget) {
        auto it = m.find(id);
        if (it == m.end()) return;
        for (const auto& edge : it->second) {
            const std::string& otherId = useTarget ? edge.targetId : edge.sourceId;
            if (seen.insert(otherId).second) {
                const Node* n = getNode(otherId);
                if (n) result.push_back(n);
            }
        }
    };

    if (dir == Direction::OUT || dir == Direction::BOTH) addFrom(adj_,   true);
    if (dir == Direction::IN  || dir == Direction::BOTH) addFrom(adjIn_, false);
    return result;
}

std::vector<const Node*> Graph::getInNeighbours(const std::string& id) const {
    return getNeighbours(id, Direction::IN);
}

std::vector<const Edge*> Graph::getOutEdges(const std::string& id) const {
    std::vector<const Edge*> result;
    auto it = adj_.find(id);
    if (it == adj_.end()) return result;
    for (const auto& e : it->second)
        result.push_back(&e);
    return result;
}

std::vector<const Edge*> Graph::getInEdges(const std::string& id) const {
    std::vector<const Edge*> result;
    auto it = adjIn_.find(id);
    if (it == adjIn_.end()) return result;
    for (const auto& e : it->second)
        result.push_back(&e);
    return result;
}

int Graph::outDegree(const std::string& id) const {
    auto it = adj_.find(id);
    return (it == adj_.end()) ? 0 : (int)it->second.size();
}

int Graph::inDegree(const std::string& id) const {
    auto it = adjIn_.find(id);
    return (it == adjIn_.end()) ? 0 : (int)it->second.size();
}

int Graph::degree(const std::string& id) const {
    return inDegree(id) + outDegree(id);
}

std::vector<const Node*> Graph::getNodesByType(EntityType type) const {
    std::vector<const Node*> result;
    for (const auto& kv : nodes_)
        if (kv.second.type == type)
            result.push_back(&kv.second);
    return result;
}

std::vector<const Node*> Graph::getAllNodes() const {
    std::vector<const Node*> result;
    result.reserve(nodes_.size());
    for (const auto& kv : nodes_)
        result.push_back(&kv.second);
    return result;
}

std::vector<const Edge*> Graph::getAllEdges() const {
    std::vector<const Edge*> result;
    result.reserve(allEdges_.size());
    for (const auto& e : allEdges_)
        result.push_back(&e);
    return result;
}

void Graph::clear() {
    nodes_.clear();
    adj_.clear();
    adjIn_.clear();
    allEdges_.clear();
}

bool Graph::setNodeProperty(const std::string& nodeId,
                             const std::string& key,
                             const std::string& value) {
    auto it = nodes_.find(nodeId);
    if (it == nodes_.end()) return false;
    it->second.properties[key] = value;
    return true;
}

bool Graph::removeNode(const std::string& id) {
    if (!nodes_.count(id)) return false;
    nodes_.erase(id);
    adj_.erase(id);
    adjIn_.erase(id);
    // drop edges of other nodes that point to / come from `id`
    for (auto& kv : adj_) {
        auto& v = kv.second;
        v.erase(std::remove_if(v.begin(), v.end(),
                [&](const Edge& e) { return e.targetId == id; }), v.end());
    }
    for (auto& kv : adjIn_) {
        auto& v = kv.second;
        v.erase(std::remove_if(v.begin(), v.end(),
                [&](const Edge& e) { return e.sourceId == id; }), v.end());
    }
    allEdges_.erase(std::remove_if(allEdges_.begin(), allEdges_.end(),
            [&](const Edge& e) { return e.sourceId == id || e.targetId == id; }),
            allEdges_.end());
    return true;
}

bool Graph::removeEdge(const std::string& srcId, const std::string& tgtId,
                       RelationType relation) {
    if (!nodes_.count(srcId) || !nodes_.count(tgtId)) return false;
    auto match = [&](const Edge& e) {
        return e.sourceId == srcId && e.targetId == tgtId && e.relation == relation;
    };
    bool found = false;
    auto& outv = adj_[srcId];
    size_t before = outv.size();
    outv.erase(std::remove_if(outv.begin(), outv.end(), match), outv.end());
    if (outv.size() != before) found = true;
    auto& inv = adjIn_[tgtId];
    inv.erase(std::remove_if(inv.begin(), inv.end(), match), inv.end());
    allEdges_.erase(std::remove_if(allEdges_.begin(), allEdges_.end(), match), allEdges_.end());
    return found;
}

void Graph::print() const {
    printf("=== Grafo de Conhecimento CTI ===\n");
    printf("Nós: %d  |  Relações: %d\n\n", nodeCount(), edgeCount());

    printf("--- Nós ---\n");
    for (const auto& kv : nodes_)
        kv.second.print();

    printf("\n--- Relações ---\n");
    for (const auto& e : allEdges_)
        e.print();
    printf("=================================\n");
}
