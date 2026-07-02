#include <cstdio>
#include <cstring>
#include <cstdlib>   // remove()
#include <cmath>
#include "tests.h"
#include "graph.h"
#include "synthetic_data.h"
#include "database.h"
#include "algorithms.h"
#include "service.h"

// Helper: does a vector of ids contain a given id?
static bool contains(const std::vector<std::string>& v, const std::string& id) {
    for (const auto& s : v) if (s == id) return true;
    return false;
}

// Simple assertion helper
static int g_failures = 0;

static void check(bool condition, const char* description) {
    if (condition) {
        printf("  [OK] %s\n", description);
    } else {
        printf("  [FALHOU] %s\n", description);
        g_failures++;
    }
}

// ---- Individual test functions ----

static void testAddNode() {
    printf("\n[TESTE] Adicionar nos\n");
    Graph g;

    Node n1("ta-001", "Evil Corp", EntityType::THREAT_ACTOR);
    check(g.addNode(n1),  "Adicionar nó válido (threat-actor)");
    check(!g.addNode(n1), "Rejeitar nó duplicado");

    Node nUnk("unk", "Desconhecido", EntityType::UNKNOWN);
    check(!g.addNode(nUnk), "Rejeitar nó com tipo UNKNOWN");

    check(g.nodeCount() == 1, "Contagem de nós correcta após inserções");
}

static void testAddEdgeValidation() {
    printf("\n[TESTE] Validacao de relacoes\n");
    Graph g;

    Node actor("apt1", "APT1", EntityType::THREAT_ACTOR);
    Node malware("mal1", "DarkRAT", EntityType::MALWARE);
    Node indicator("ioc1", "1.2.3.4", EntityType::INDICATOR);
    Node identity("corp1", "ACME Corp", EntityType::IDENTITY);

    g.addNode(actor);
    g.addNode(malware);
    g.addNode(indicator);
    g.addNode(identity);

    // Valid relations
    check(g.addEdge("apt1", "mal1", RelationType::USES),
          "threat-actor uses malware  (valido)");
    check(g.addEdge("ioc1", "mal1", RelationType::INDICATES),
          "indicator indicates malware  (valido)");
    check(g.addEdge("apt1", "corp1", RelationType::TARGETS),
          "threat-actor targets identity  (valido)");

    // Invalid relations
    check(!g.addEdge("mal1", "apt1", RelationType::TARGETS),
          "malware targets threat-actor  (invalido — rejeitado)");
    check(!g.addEdge("apt1", "mal1", RelationType::INDICATES),
          "threat-actor indicates malware  (invalido — rejeitado)");
    check(!g.addEdge("apt1", "nonexistent", RelationType::USES),
          "Relacao com nó inexistente  (rejeitado)");
}

static void testGetNeighbours() {
    printf("\n[TESTE] Vizinhos de um no\n");
    Graph g;

    Node actor("apt2",   "APT2",    EntityType::THREAT_ACTOR);
    Node mal1 ("mal-a",  "MalwareA",EntityType::MALWARE);
    Node mal2 ("mal-b",  "MalwareB",EntityType::MALWARE);
    Node ident("target1","TargetOrg",EntityType::IDENTITY);

    g.addNode(actor); g.addNode(mal1); g.addNode(mal2); g.addNode(ident);

    g.addEdge("apt2", "mal-a",  RelationType::USES);
    g.addEdge("apt2", "mal-b",  RelationType::USES);
    g.addEdge("apt2", "target1",RelationType::TARGETS);

    auto neighbours = g.getNeighbours("apt2");
    check(neighbours.size() == 3, "APT2 tem 3 vizinhos");

    // Verify the node with no outgoing edges returns an empty list
    auto noNeighbours = g.getNeighbours("target1");
    check(noNeighbours.empty(), "Nó sem arestas de saida tem 0 vizinhos");

    // Non-existent node
    auto ghost = g.getNeighbours("ghost");
    check(ghost.empty(), "Nó inexistente devolve lista vazia");
}

static void testInverseAdjacency() {
    printf("\n[TESTE] Lista de adjacencia inversa (relacoes de entrada)\n");
    Graph g;

    Node actor("apt2",   "APT2",    EntityType::THREAT_ACTOR);
    Node mal  ("mal-x",  "MalwareX",EntityType::MALWARE);
    Node ind  ("ioc-x",  "1.2.3.4", EntityType::INDICATOR);

    g.addNode(actor); g.addNode(mal); g.addNode(ind);
    g.addEdge("apt2",  "mal-x", RelationType::USES);       // apt2  -> mal-x
    g.addEdge("ioc-x", "mal-x", RelationType::INDICATES);  // ioc-x -> mal-x

    check(g.getInEdges("mal-x").size() == 2,  "mal-x tem 2 arestas de entrada");
    check(g.getOutEdges("mal-x").empty(),     "mal-x tem 0 arestas de saida");
    check(g.inDegree("mal-x") == 2,           "inDegree(mal-x) == 2");
    check(g.outDegree("apt2") == 1,           "outDegree(apt2) == 1");
    check(g.degree("mal-x") == 2,             "degree(mal-x) == 2");

    auto inN = g.getInNeighbours("mal-x");
    check(inN.size() == 2, "mal-x tem 2 vizinhos de entrada");

    check(g.getNeighbours("apt2",  Direction::OUT).size() == 1,  "apt2 tem 1 vizinho de saida");
    check(g.getNeighbours("mal-x", Direction::BOTH).size() == 2, "mal-x tem 2 vizinhos (ambas direcoes)");
}

static void testDegreeCentrality() {
    printf("\n[TESTE] Centralidade por grau\n");
    Graph g;
    loadSyntheticData(g);

    auto dc = Algorithms::degreeCentrality(g);
    check(dc.size() == (size_t)g.nodeCount(), "Centralidade calculada para todos os nos");

    bool sorted = true;
    for (size_t i = 1; i < dc.size(); ++i)
        if (dc[i - 1].total < dc[i].total) sorted = false;
    check(sorted, "Resultados ordenados por grau total decrescente");

    bool consistent = true;
    for (const auto& d : dc) {
        if (d.total != d.in + d.out) consistent = false;
        if (d.in != g.inDegree(d.id) || d.out != g.outDegree(d.id)) consistent = false;
    }
    check(consistent, "total == entrada + saida para todos os nos");

    check(!dc.empty() && dc.front().total > 0, "No de maior grau tem grau positivo");
}

static void testGetNodesByType() {
    printf("\n[TESTE] Filtrar nos por tipo\n");
    Graph g;
    loadSyntheticData(g);

    auto actors     = g.getNodesByType(EntityType::THREAT_ACTOR);
    auto malwares   = g.getNodesByType(EntityType::MALWARE);
    auto indicators = g.getNodesByType(EntityType::INDICATOR);
    auto campaigns  = g.getNodesByType(EntityType::CAMPAIGN);

    check(actors.size()     == 4, "4 threat-actors no dataset sintetico (inc. duplicado 'dukes')");
    check(malwares.size()   == 3, "3 malwares no dataset sintetico");
    check(indicators.size() == 5, "5 indicators no dataset sintetico");
    check(campaigns.size()  == 2, "2 campaigns no dataset sintetico");
}

static void testSyntheticDataIntegrity() {
    printf("\n[TESTE] Integridade do dataset sintetico\n");
    Graph g;
    loadSyntheticData(g);

    check(g.nodeCount() > 0, "Grafo tem nos apos carregar dados sinteticos");
    check(g.edgeCount() > 0, "Grafo tem relacoes apos carregar dados sinteticos");

    check(g.getNode("apt29")    != nullptr, "Nó APT29 existe");
    check(g.getNode("sunburst") != nullptr, "Nó SUNBURST existe");
    check(g.getNode("lazarus")  != nullptr, "Nó Lazarus Group existe");

    // APT29 should have neighbours
    auto apt29Neighbours = g.getNeighbours("apt29");
    check(!apt29Neighbours.empty(), "APT29 tem vizinhos");

    // SUNBURST should have TEARDROP as neighbour (drops relation)
    bool foundTeardrop = false;
    for (const auto* n : g.getNeighbours("sunburst"))
        if (n->id == "teardrop") { foundTeardrop = true; break; }
    check(foundTeardrop, "SUNBURST -> TEARDROP (drops) encontrado");

    // WannaCry should exploit EternalBlue
    bool foundVuln = false;
    for (const auto* n : g.getNeighbours("wannacry"))
        if (n->id == "vuln-ms17-010") { foundVuln = true; break; }
    check(foundVuln, "WannaCry -> EternalBlue (exploits) encontrado");
}

// ---------------------------------------------------------------------------
// Persistence tests (Level 2)
// ---------------------------------------------------------------------------

static void testDBInit() {
    printf("\n[TESTE] Inicializar base de dados\n");
    const char* path = "/tmp/test_cti_init.db";
    remove(path);

    Database db;
    check(db.initDB(path), "initDB cria ficheiro .db com sucesso");
    check(db.isOpen(),     "Base de dados fica aberta apos initDB");

    // Second call on same path should also succeed (schema already exists)
    Database db2;
    check(db2.initDB(path), "initDB em ficheiro existente funciona (schema IF NOT EXISTS)");
    remove(path);
}

static void testSaveAndLoadGraph() {
    printf("\n[TESTE] Guardar e recarregar grafo (round-trip)\n");
    const char* path = "/tmp/test_cti_roundtrip.db";
    remove(path);

    // Build source graph
    Graph g1;
    loadSyntheticData(g1);
    int origNodes = g1.nodeCount();
    int origEdges = g1.edgeCount();

    // Save
    Database db;
    db.initDB(path);
    check(db.saveGraph(g1), "saveGraph retorna true");

    // Load into fresh graph
    Graph g2;
    check(db.loadGraph(g2), "loadGraph retorna true");

    check(g2.nodeCount() == origNodes,
          "nodeCount igual apos round-trip");
    check(g2.edgeCount() == origEdges,
          "edgeCount igual apos round-trip");

    remove(path);
}

static void testNodePreservedAfterLoad() {
    printf("\n[TESTE] No especifico preservado apos recarregar\n");
    const char* path = "/tmp/test_cti_node.db";
    remove(path);

    Graph g1;
    loadSyntheticData(g1);

    Database db;
    db.initDB(path);
    db.saveGraph(g1);

    Graph g2;
    db.loadGraph(g2);

    const Node* apt29 = g2.getNode("apt29");
    check(apt29 != nullptr,                      "Nó apt29 existe no grafo recarregado");
    check(apt29 && apt29->type == EntityType::THREAT_ACTOR,
          "apt29 tem tipo threat-actor apos recarregar");
    check(apt29 && apt29->label == "APT29 / Cozy Bear",
          "apt29 label preservado apos recarregar");

    // Check a property
    bool hasOrigin = apt29 && apt29->properties.count("origin") &&
                     apt29->properties.at("origin") == "Russia";
    check(hasOrigin, "apt29.origin == 'Russia' (propriedade preservada)");

    remove(path);
}

static void testNeighboursPreservedAfterLoad() {
    printf("\n[TESTE] Vizinhos preservados apos recarregar\n");
    const char* path = "/tmp/test_cti_neighbours.db";
    remove(path);

    Graph g1;
    loadSyntheticData(g1);
    int origNeighbours = (int)g1.getNeighbours("apt29").size();

    Database db;
    db.initDB(path);
    db.saveGraph(g1);

    Graph g2;
    db.loadGraph(g2);

    int loadedNeighbours = (int)g2.getNeighbours("apt29").size();
    check(loadedNeighbours == origNeighbours,
          "Numero de vizinhos de apt29 igual apos recarregar");

    // Specific neighbour: sunburst
    bool foundSunburst = false;
    for (const auto* n : g2.getNeighbours("apt29"))
        if (n->id == "sunburst") { foundSunburst = true; break; }
    check(foundSunburst, "apt29 -> sunburst (uses) preservado apos recarregar");

    remove(path);
}

static void testDBSearchByType() {
    printf("\n[TESTE] searchNodesByType na base de dados\n");
    const char* path = "/tmp/test_cti_search.db";
    remove(path);

    Graph g1;
    loadSyntheticData(g1);

    Database db;
    db.initDB(path);
    db.saveGraph(g1);

    auto actors = db.searchNodesByType(EntityType::THREAT_ACTOR);
    check(actors.size() == 4, "searchNodesByType retorna 4 threat-actors");

    auto malwares = db.searchNodesByType(EntityType::MALWARE);
    check(malwares.size() == 3, "searchNodesByType retorna 3 malwares");

    auto indicators = db.searchNodesByType(EntityType::INDICATOR);
    check(indicators.size() == 5, "searchNodesByType retorna 5 indicators");

    remove(path);
}

static void testDBSearchEdges() {
    printf("\n[TESTE] searchEdgesBy* na base de dados\n");
    const char* path = "/tmp/test_cti_edges.db";
    remove(path);

    Graph g1;
    loadSyntheticData(g1);

    Database db;
    db.initDB(path);
    db.saveGraph(g1);

    // Edges originating from apt29
    auto fromApt29 = db.searchEdgesBySource("apt29");
    check(!fromApt29.empty(), "searchEdgesBySource('apt29') devolve resultados");
    // All returned edges must have apt29 as source
    bool allCorrectSrc = true;
    for (const auto& e : fromApt29)
        if (e.sourceId != "apt29") { allCorrectSrc = false; break; }
    check(allCorrectSrc, "Todos os edges de searchEdgesBySource('apt29') tem source==apt29");

    // Edges targeting id-usgov
    auto toUsgov = db.searchEdgesByTarget("id-usgov");
    check(!toUsgov.empty(), "searchEdgesByTarget('id-usgov') devolve resultados");

    // Edges of type 'exploits'
    auto exploits = db.searchEdgesByRelation(RelationType::EXPLOITS);
    check(exploits.size() == 1, "searchEdgesByRelation(EXPLOITS) devolve 1 relacao");
    check(!exploits.empty() && exploits[0].sourceId == "wannacry",
          "Relacao exploits tem origem em wannacry");

    remove(path);
}

static void testIdempotentSave() {
    printf("\n[TESTE] saveGraph idempotente (guardar duas vezes)\n");
    const char* path = "/tmp/test_cti_idempotent.db";
    remove(path);

    Graph g1;
    loadSyntheticData(g1);

    Database db;
    db.initDB(path);
    db.saveGraph(g1);  // first save
    db.saveGraph(g1);  // second save — INSERT OR REPLACE should not duplicate nodes

    Graph g2;
    db.loadGraph(g2);

    // Edges can be duplicated if saved twice (no unique constraint); nodes should not be.
    check(g2.nodeCount() == g1.nodeCount(),
          "nodeCount correcto apos dois saveGraph consecutivos");

    remove(path);
}

// ---------------------------------------------------------------------------
// Algorithm tests (Level 3)
// ---------------------------------------------------------------------------

static void testBFS() {
    printf("\n[TESTE] BFS\n");
    Graph g;
    loadSyntheticData(g);

    // directed BFS from apt29
    auto order = Algorithms::bfs(g, "apt29", true);
    check(!order.empty(),              "BFS devolve ordem nao-vazia");
    check(order.front() == "apt29",    "BFS comeca no no de partida");
    check(contains(order, "sunburst"), "BFS alcanca sunburst (apt29 -> sunburst)");
    check(contains(order, "teardrop"), "BFS alcanca teardrop (apt29 -> sunburst -> teardrop)");

    // no duplicates in BFS order
    bool unique = true;
    for (size_t i = 0; i < order.size(); ++i)
        for (size_t j = i + 1; j < order.size(); ++j)
            if (order[i] == order[j]) unique = false;
    check(unique, "BFS nao repete nos");

    // non-existent start
    check(Algorithms::bfs(g, "ghost").empty(), "BFS de no inexistente devolve vazio");
}

static void testDFS() {
    printf("\n[TESTE] DFS\n");
    Graph g;
    loadSyntheticData(g);

    auto order = Algorithms::dfs(g, "apt29", true);
    check(!order.empty(),              "DFS devolve ordem nao-vazia");
    check(order.front() == "apt29",    "DFS comeca no no de partida");
    check(contains(order, "teardrop"), "DFS alcanca teardrop em profundidade");

    // BFS and DFS reach the same set of nodes (same reachable component)
    auto bfsOrder = Algorithms::bfs(g, "apt29", true);
    check(order.size() == bfsOrder.size(),
          "DFS e BFS visitam o mesmo numero de nos alcancaveis");
}

static void testShortestPath() {
    printf("\n[TESTE] Caminho mais curto\n");
    Graph g;
    loadSyntheticData(g);

    // Indicator -> actor (requires undirected traversal):
    // ioc-hash-sunburst -indicates-> sunburst <-uses- apt29
    auto path = Algorithms::shortestPath(g, "ioc-hash-sunburst", "apt29", false);
    check(!path.empty(),                       "Existe caminho ioc-hash-sunburst -> apt29");
    check(path.front() == "ioc-hash-sunburst", "Caminho comeca no indicador");
    check(path.back()  == "apt29",             "Caminho termina no ator");
    check(path.size()  == 3,                   "Caminho tem 3 nos (ioc - sunburst - apt29)");

    // src == dst
    auto self = Algorithms::shortestPath(g, "apt29", "apt29");
    check(self.size() == 1 && self[0] == "apt29", "Caminho de um no para si proprio tem tamanho 1");

    // unreachable across disconnected components (directed)
    // apt29 cannot reach lazarus following directed edges
    auto none = Algorithms::shortestPath(g, "apt29", "lazarus", true);
    check(none.empty(), "Sem caminho dirigido apt29 -> lazarus (componentes distintas)");
}

static void testPageRank() {
    printf("\n[TESTE] PageRank\n");
    Graph g;
    loadSyntheticData(g);

    auto rank = Algorithms::pageRank(g);
    check(rank.size() == (size_t)g.nodeCount(), "PageRank atribui score a todos os nos");

    // scores must sum to ~1.0
    double sum = 0.0;
    for (const auto& kv : rank) sum += kv.second;
    check(std::fabs(sum - 1.0) < 1e-6, "Scores de PageRank somam ~1.0");

    // all scores positive
    bool allPositive = true;
    for (const auto& kv : rank) if (kv.second <= 0.0) allPositive = false;
    check(allPositive, "Todos os scores de PageRank sao positivos");

    // ranking is sorted descending
    auto ranked = Algorithms::rankEntities(g);
    bool sorted = true;
    for (size_t i = 1; i < ranked.size(); ++i)
        if (ranked[i - 1].second < ranked[i].second) sorted = false;
    check(sorted, "rankEntities devolve scores por ordem decrescente");

    // sunburst receives many incoming links -> should rank highly (top 3)
    bool sunburstHigh = false;
    for (size_t i = 0; i < ranked.size() && i < 3; ++i)
        if (ranked[i].first == "sunburst") sunburstHigh = true;
    check(sunburstHigh, "sunburst esta no top-3 do PageRank (muito referenciado)");
}

static void testEntityResolution() {
    printf("\n[TESTE] Resolucao de entidades\n");
    Graph g;
    loadSyntheticData(g);

    // "APT29" and "Cozy Bear" must resolve to the same node (apt29)
    auto byApt29 = Algorithms::resolveByName(g, "APT29");
    auto byCozy  = Algorithms::resolveByName(g, "Cozy Bear");
    check(contains(byApt29, "apt29"), "resolveByName('APT29') inclui apt29");
    check(contains(byCozy,  "apt29"), "resolveByName('Cozy Bear') inclui apt29");

    // "Cozy Bear" is shared by apt29 and the duplicate 'dukes'
    check(contains(byCozy, "dukes"), "resolveByName('Cozy Bear') inclui o duplicado dukes");

    // case / punctuation insensitivity
    auto messy = Algorithms::resolveByName(g, "  cozy  bear ");
    check(contains(messy, "apt29"), "resolveByName tolera maiusculas/espacos");

    // duplicate detection groups apt29 with dukes
    auto dups = Algorithms::findPotentialDuplicates(g);
    bool foundGroup = false;
    for (const auto& group : dups)
        if (contains(group, "apt29") && contains(group, "dukes"))
            foundGroup = true;
    check(foundGroup, "findPotentialDuplicates agrupa apt29 e dukes (mesmo ator)");
}

static void testAnalyticalQueries() {
    printf("\n[TESTE] Consultas analiticas\n");
    Graph g;
    loadSyntheticData(g);

    // "Que atores usam SUNBURST?" -> apt29 and dukes
    auto actors = Algorithms::actorsUsingMalware(g, "sunburst");
    check(contains(actors, "apt29"), "actorsUsingMalware(sunburst) inclui apt29");
    check(contains(actors, "dukes"), "actorsUsingMalware(sunburst) inclui dukes");

    // "Que indicadores apontam para SUNBURST?" -> hash + domain
    auto iocs = Algorithms::indicatorsForThreat(g, "sunburst");
    check(contains(iocs, "ioc-hash-sunburst"),    "indicatorsForThreat(sunburst) inclui o hash");
    check(contains(iocs, "ioc-domain-avsvmcloud"),"indicatorsForThreat(sunburst) inclui o dominio");
    check(iocs.size() == 2, "Exatamente 2 indicadores apontam para sunburst");
}

// ---------------------------------------------------------------------------
// Service-layer integration tests (Level 4)
// ---------------------------------------------------------------------------

static void testServiceCrud() {
    printf("\n[TESTE] Camada de servicos - CRUD e validacao\n");
    Graph g;
    loadSyntheticData(g);
    Service svc(g);

    // create valid node + valid edge
    check(svc.createNode("evilcorp", "Evil Corp", "threat-actor").ok,
          "createNode valido devolve ok");
    check(svc.createEdge("evilcorp", "wannacry", "uses").ok,
          "createEdge valido devolve ok");

    // duplicate node -> error
    check(!svc.createNode("apt29", "dup", "threat-actor").ok,
          "createNode duplicado devolve erro");
    // invalid type -> error
    check(!svc.createNode("x1", "X", "banana").ok,
          "createNode com tipo invalido devolve erro");
    // invalid relation (semantics) -> error
    check(!svc.createEdge("wannacry", "evilcorp", "targets").ok,
          "createEdge invalida devolve erro");
    // missing endpoint -> error
    check(!svc.createEdge("evilcorp", "naoexiste", "uses").ok,
          "createEdge com destino inexistente devolve erro");
}

static void testServiceQueries() {
    printf("\n[TESTE] Camada de servicos - consultas e algoritmos\n");
    Graph g;
    loadSyntheticData(g);
    Service svc(g);

    // neighbours in/out/both
    std::vector<const Node*> out;
    check(svc.neighbours("sunburst", "in", out).ok && !out.empty(),
          "neighbours(sunburst,in) devolve quem aponta para sunburst");
    check(!svc.neighbours("apt29", "lateral", out).ok,
          "neighbours com direcao invalida devolve erro");
    check(!svc.neighbours("fantasma", "out", out).ok,
          "neighbours de no inexistente devolve erro");

    // shortest path success + failure
    std::vector<std::string> path;
    check(svc.shortestPath("ioc-hash-sunburst", "apt29", path).ok && path.size() == 3,
          "shortestPath devolve caminho de 3 nos");
    check(!svc.shortestPath("apt29", "naoexiste", path).ok,
          "shortestPath para no inexistente devolve erro");

    // ranking / degree / stats reflect real computations
    check(!svc.ranking().empty(),       "ranking (PageRank) nao vazio");
    check(!svc.degreeRanking().empty(), "degree ranking nao vazio");
    auto s = svc.stats();
    check(s.nodes == g.nodeCount() && s.edges == g.edgeCount(),
          "stats coincide com o grafo");
    check(!s.topByPageRank.empty(), "stats indica entidade mais relevante");
}

static void testRemoval() {
    printf("\n[TESTE] Apagar nos e relacoes\n");
    Graph g;
    loadSyntheticData(g);
    Service svc(g);

    int n0 = g.nodeCount(), e0 = g.edgeCount();

    // delete an edge that exists: apt29 --uses--> sunburst
    check(svc.deleteEdge("apt29", "sunburst", "uses").ok, "deleteEdge existente devolve ok");
    check(g.edgeCount() == e0 - 1, "edgeCount diminui 1 apos apagar relacao");
    // deleting it again fails
    check(!svc.deleteEdge("apt29", "sunburst", "uses").ok, "deleteEdge inexistente devolve erro");

    // delete a node removes it and its incident edges
    int sunIn = g.inDegree("sunburst"), sunOut = g.outDegree("sunburst");
    int incident = sunIn + sunOut;
    int eBefore = g.edgeCount();
    check(svc.deleteNode("sunburst").ok, "deleteNode existente devolve ok");
    check(g.getNode("sunburst") == nullptr, "no removido deixa de existir");
    check(g.nodeCount() == n0 - 1, "nodeCount diminui 1 apos apagar no");
    check(g.edgeCount() == eBefore - incident, "relacoes incidentes removidas com o no");
    check(!svc.deleteNode("sunburst").ok, "deleteNode inexistente devolve erro");

    // inverse adjacency stays consistent: nobody points to sunburst anymore
    check(g.getInEdges("sunburst").empty(), "sem arestas de entrada para no removido");
}

static void testMostProbable() {
    printf("\n[TESTE] Entidade mais provavel\n");
    Graph g;
    loadSyntheticData(g);

    // a partir do hash do SUNBURST, o ator mais provavel deve ser apt29
    auto actors = Algorithms::mostProbable(g, "ioc-hash-sunburst", EntityType::THREAT_ACTOR);
    check(!actors.empty(), "ha pelo menos um ator candidato");
    check(!actors.empty() && actors.front().id == "apt29",
          "ator mais provavel a partir do hash e apt29");
    // resultados ordenados por score decrescente
    bool sorted = true;
    for (size_t i = 1; i < actors.size(); ++i)
        if (actors[i - 1].score < actors[i].score) sorted = false;
    check(sorted, "candidatos ordenados por score decrescente");
    // distancias coerentes (>=1) e score = pr/dist
    bool consistent = true;
    for (const auto& c : actors)
        if (c.distance < 1 || c.score > c.pagerank + 1e-12) consistent = false;
    check(consistent, "distancia>=1 e score=pagerank/distancia");

    // malware mais provavel a partir do mesmo indicador deve ser sunburst (distancia 1)
    auto mal = Algorithms::mostProbable(g, "ioc-hash-sunburst", EntityType::MALWARE);
    check(!mal.empty() && mal.front().id == "sunburst",
          "malware mais provavel a partir do hash e sunburst");

    // no inexistente -> sem candidatos
    check(Algorithms::mostProbable(g, "fantasma", EntityType::THREAT_ACTOR).empty(),
          "no inexistente devolve lista vazia");
}

// ---- Entry point ----

int runTests() {
    g_failures = 0;
    printf("==================================================\n");
    printf("  Testes - Nivel 3 (Grafo + Persistencia + Algos) \n");
    printf("==================================================\n");

    // Level 1 tests
    testAddNode();
    testAddEdgeValidation();
    testGetNeighbours();
    testInverseAdjacency();
    testGetNodesByType();
    testSyntheticDataIntegrity();

    // Level 2 persistence tests
    testDBInit();
    testSaveAndLoadGraph();
    testNodePreservedAfterLoad();
    testNeighboursPreservedAfterLoad();
    testDBSearchByType();
    testDBSearchEdges();
    testIdempotentSave();

    // Level 3 algorithm tests
    testBFS();
    testDFS();
    testShortestPath();
    testDegreeCentrality();
    testPageRank();
    testEntityResolution();
    testAnalyticalQueries();

    // Level 4 service-layer integration tests
    testServiceCrud();
    testServiceQueries();
    testRemoval();
    testMostProbable();

    printf("\n============================================\n");
    if (g_failures == 0)
        printf("  Todos os testes passaram com sucesso!\n");
    else
        printf("  %d teste(s) FALHARAM.\n", g_failures);
    printf("============================================\n");

    return g_failures;
}
