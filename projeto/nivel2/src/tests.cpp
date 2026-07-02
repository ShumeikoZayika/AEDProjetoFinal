#include <cstdio>
#include <cstring>
#include <cstdlib>   // remove()
#include "tests.h"
#include "graph.h"
#include "synthetic_data.h"
#include "database.h"

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

static void testGetNodesByType() {
    printf("\n[TESTE] Filtrar nos por tipo\n");
    Graph g;
    loadSyntheticData(g);

    auto actors     = g.getNodesByType(EntityType::THREAT_ACTOR);
    auto malwares   = g.getNodesByType(EntityType::MALWARE);
    auto indicators = g.getNodesByType(EntityType::INDICATOR);
    auto campaigns  = g.getNodesByType(EntityType::CAMPAIGN);

    check(actors.size()     == 3, "3 threat-actors no dataset sintetico");
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
    check(actors.size() == 3, "searchNodesByType retorna 3 threat-actors");

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

// ---- Entry point ----

int runTests() {
    g_failures = 0;
    printf("============================================\n");
    printf("  Testes - Nivel 2 (Grafo + Persistencia)  \n");
    printf("============================================\n");

    // Level 1 tests
    testAddNode();
    testAddEdgeValidation();
    testGetNeighbours();
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

    printf("\n============================================\n");
    if (g_failures == 0)
        printf("  Todos os testes passaram com sucesso!\n");
    else
        printf("  %d teste(s) FALHARAM.\n", g_failures);
    printf("============================================\n");

    return g_failures;
}
