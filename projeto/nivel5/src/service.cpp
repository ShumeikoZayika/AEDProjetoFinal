#include "service.h"

// ---- helpers ---------------------------------------------------------------

static Direction parseDirection(const std::string& s, bool& ok) {
    ok = true;
    if (s.empty() || s == "out")  return Direction::OUT;
    if (s == "in")                return Direction::IN;
    if (s == "both")              return Direction::BOTH;
    ok = false;
    return Direction::OUT;
}

// ---- CRUD ------------------------------------------------------------------

OpResult Service::createNode(const std::string& id, const std::string& label,
                             const std::string& typeStr) {
    if (id.empty())
        return OpResult::error("O identificador do nó não pode ser vazio.");
    if (g_.getNode(id))
        return OpResult::error("Já existe um nó com o id '" + id + "'.");

    EntityType type = stringToEntityType(typeStr);
    if (type == EntityType::UNKNOWN)
        return OpResult::error("Tipo de entidade inválido: '" + typeStr +
                               "'. Use threat-actor, malware, indicator, campaign, "
                               "vulnerability, identity, attack-pattern ou tool.");

    Node n(id, label.empty() ? id : label, type);
    if (!g_.addNode(n))
        return OpResult::error("Não foi possível adicionar o nó '" + id + "'.");
    return OpResult::success("Nó '" + id + "' criado (" + typeStr + ").");
}

OpResult Service::createEdge(const std::string& srcId, const std::string& tgtId,
                             const std::string& relationStr) {
    if (!g_.getNode(srcId))
        return OpResult::error("Nó de origem '" + srcId + "' não existe.");
    if (!g_.getNode(tgtId))
        return OpResult::error("Nó de destino '" + tgtId + "' não existe.");

    RelationType rel = stringToRelationType(relationStr);
    if (rel == RelationType::UNKNOWN)
        return OpResult::error("Tipo de relação inválido: '" + relationStr + "'.");

    if (!g_.addEdge(srcId, tgtId, rel))
        return OpResult::error("Relação inválida segundo a matriz de relações "
                               "permitidas: " + srcId + " --" + relationStr +
                               "--> " + tgtId + ".");
    return OpResult::success("Relação criada: " + srcId + " --" + relationStr +
                             "--> " + tgtId + ".");
}

const Node* Service::getNode(const std::string& id) const {
    return g_.getNode(id);
}

OpResult Service::deleteNode(const std::string& id) {
    if (!g_.getNode(id))
        return OpResult::error("Nó '" + id + "' não existe.");
    g_.removeNode(id);
    return OpResult::success("Nó '" + id + "' removido (e relações incidentes).");
}

OpResult Service::deleteEdge(const std::string& srcId, const std::string& tgtId,
                             const std::string& relationStr) {
    if (!g_.getNode(srcId) || !g_.getNode(tgtId))
        return OpResult::error("Origem ou destino inexistente.");
    RelationType rel = stringToRelationType(relationStr);
    if (rel == RelationType::UNKNOWN)
        return OpResult::error("Tipo de relação inválido: '" + relationStr + "'.");
    if (!g_.removeEdge(srcId, tgtId, rel))
        return OpResult::error("Não existe a relação " + srcId + " --" + relationStr +
                               "--> " + tgtId + ".");
    return OpResult::success("Relação removida: " + srcId + " --" + relationStr +
                             "--> " + tgtId + ".");
}

std::vector<const Node*> Service::listNodesByType(const std::string& typeStr,
                                                  bool& validType) const {
    EntityType type = stringToEntityType(typeStr);
    validType = (type != EntityType::UNKNOWN);
    if (!validType) return {};
    return g_.getNodesByType(type);
}

// ---- queries / algorithms --------------------------------------------------

OpResult Service::neighbours(const std::string& id, const std::string& dirStr,
                             std::vector<const Node*>& out) const {
    if (!g_.getNode(id))
        return OpResult::error("Nó '" + id + "' não existe.");
    bool ok;
    Direction dir = parseDirection(dirStr, ok);
    if (!ok)
        return OpResult::error("Direção inválida: '" + dirStr +
                               "'. Use out, in ou both.");
    out = g_.getNeighbours(id, dir);
    return OpResult::success("");
}

OpResult Service::shortestPath(const std::string& srcId, const std::string& dstId,
                               std::vector<std::string>& path) const {
    if (!g_.getNode(srcId))
        return OpResult::error("Nó de origem '" + srcId + "' não existe.");
    if (!g_.getNode(dstId))
        return OpResult::error("Nó de destino '" + dstId + "' não existe.");
    path = Algorithms::shortestPath(g_, srcId, dstId);
    if (path.empty())
        return OpResult::error("Não existe caminho entre '" + srcId +
                               "' e '" + dstId + "'.");
    return OpResult::success("");
}

std::vector<std::pair<std::string, double>> Service::ranking() const {
    return Algorithms::rankEntities(g_);
}

std::vector<Algorithms::DegreeCentrality> Service::degreeRanking() const {
    return Algorithms::degreeCentrality(g_);
}

// ---- statistics ------------------------------------------------------------

Service::Stats Service::stats() const {
    Stats s;
    s.nodes = g_.nodeCount();
    s.edges = g_.edgeCount();
    for (const Node* n : g_.getAllNodes())
        s.nodesByType[entityTypeToString(n->type)]++;

    auto pr = Algorithms::rankEntities(g_);
    if (!pr.empty()) s.topByPageRank = pr.front().first;

    auto dc = Algorithms::degreeCentrality(g_);
    if (!dc.empty()) s.topByDegree = dc.front().id;
    return s;
}

// ---- persistence -----------------------------------------------------------

OpResult Service::save() {
    if (!db_ || !db_->isOpen())
        return OpResult::error("Base de dados não disponível.");
    if (!db_->saveGraph(g_))
        return OpResult::error("Falha ao guardar o grafo na base de dados.");
    return OpResult::success("Grafo guardado na base de dados.");
}

OpResult Service::reload() {
    if (!db_ || !db_->isOpen())
        return OpResult::error("Base de dados não disponível.");
    if (!db_->loadGraph(g_))
        return OpResult::error("Falha ao carregar o grafo da base de dados.");
    return OpResult::success("Grafo recarregado da base de dados.");
}
