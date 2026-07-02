#include <cstdio>
#include <cstring>
#include "tests.h"
#include "graph.h"
#include "synthetic_data.h"

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

// ---- Entry point ----

int runTests() {
    g_failures = 0;
    printf("========================================\n");
    printf("  Testes - Nivel 1 (Grafo em Memoria)   \n");
    printf("========================================\n");

    testAddNode();
    testAddEdgeValidation();
    testGetNeighbours();
    testGetNodesByType();
    testSyntheticDataIntegrity();

    printf("\n========================================\n");
    if (g_failures == 0)
        printf("  Todos os testes passaram com sucesso!\n");
    else
        printf("  %d teste(s) FALHARAM.\n", g_failures);
    printf("========================================\n");

    return g_failures;
}
