#include <cstdio>
#include <cstring>
#include "src/graph.h"
#include "src/synthetic_data.h"
#include "src/database.h"
#include "src/tests.h"

static const char* DB_PATH = "cti_graph.db";

// Print neighbours with edge labels
static void showNeighbours(const Graph& g, const std::string& id) {
    const Node* node = g.getNode(id);
    if (!node) {
        printf("  [!] Nó \"%s\" não encontrado.\n", id.c_str());
        return;
    }
    printf("  Vizinhos de [%s] \"%s\":\n", id.c_str(), node->label.c_str());
    auto edges = g.getOutEdges(id);
    if (edges.empty()) { printf("    (nenhum)\n"); return; }
    for (const auto* e : edges) {
        const Node* tgt = g.getNode(e->targetId);
        printf("    --%s--> [%s] \"%s\"\n",
               relationTypeToString(e->relation).c_str(),
               e->targetId.c_str(),
               tgt ? tgt->label.c_str() : "?");
    }
}

// Show all nodes of a type
static void showByType(const Graph& g, EntityType t) {
    auto nodes = g.getNodesByType(t);
    printf("  [%s] (%zu):", entityTypeToString(t).c_str(), nodes.size());
    for (const auto* n : nodes) printf("  %s", n->id.c_str());
    printf("\n");
}

// Demonstrate the DB search helpers
static void showDBSearchDemo(Database& db) {
    printf("\n=== Pesquisa directa na base de dados ===\n");

    printf("\n-- Nós do tipo threat-actor --\n");
    for (const auto& n : db.searchNodesByType(EntityType::THREAT_ACTOR))
        printf("  [%s] \"%s\"\n", n.id.c_str(), n.label.c_str());

    printf("\n-- Relações com origem em apt29 --\n");
    for (const auto& e : db.searchEdgesBySource("apt29"))
        printf("  apt29 --%s--> %s\n",
               relationTypeToString(e.relation).c_str(), e.targetId.c_str());

    printf("\n-- Relações com destino em id-usgov --\n");
    for (const auto& e : db.searchEdgesByTarget("id-usgov"))
        printf("  %s --%s--> id-usgov\n",
               e.sourceId.c_str(), relationTypeToString(e.relation).c_str());

    printf("\n-- Todas as relações do tipo 'exploits' --\n");
    for (const auto& e : db.searchEdgesByRelation(RelationType::EXPLOITS))
        printf("  %s --%s--> %s\n",
               e.sourceId.c_str(),
               relationTypeToString(e.relation).c_str(),
               e.targetId.c_str());
}

int main(int argc, char* argv[]) {
    if (argc > 1 && strcmp(argv[1], "--testes") == 0)
        return runTests();

    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║   Grafo de Conhecimento - Cyber Threat Intelligence      ║\n");
    printf("║   Nível 2 — Persistência SQLite                          ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");

    // ---- Step 1: build in-memory graph from synthetic data ----
    printf("Passo 1 — Carregar dataset sintetico em memoria\n");
    Graph g1;
    loadSyntheticData(g1);
    printf("  %d nos, %d relacoes carregados\n\n", g1.nodeCount(), g1.edgeCount());

    // ---- Step 2: persist to SQLite ----
    printf("Passo 2 — Guardar grafo na base de dados '%s'\n", DB_PATH);
    Database db;
    if (!db.initDB(DB_PATH)) {
        printf("[FATAL] Nao foi possivel inicializar a base de dados.\n");
        return 1;
    }
    if (!db.saveGraph(g1)) {
        printf("[FATAL] Falha ao guardar o grafo.\n");
        return 1;
    }
    printf("  Grafo guardado com sucesso.\n\n");

    // ---- Step 3: load into a fresh graph and compare ----
    printf("Passo 3 — Carregar grafo da base de dados para novo objecto\n");
    Graph g2;
    if (!db.loadGraph(g2)) {
        printf("[FATAL] Falha ao carregar o grafo.\n");
        return 1;
    }
    printf("  Grafo recarregado: %d nos, %d relacoes\n", g2.nodeCount(), g2.edgeCount());

    bool match = (g1.nodeCount() == g2.nodeCount()) && (g1.edgeCount() == g2.edgeCount());
    printf("  Correspondencia com grafo original: %s\n\n", match ? "SIM" : "NAO");

    // ---- Step 4: entity breakdown of loaded graph ----
    printf("Passo 4 — Entidades por tipo (grafo recarregado)\n");
    showByType(g2, EntityType::THREAT_ACTOR);
    showByType(g2, EntityType::MALWARE);
    showByType(g2, EntityType::INDICATOR);
    showByType(g2, EntityType::CAMPAIGN);
    showByType(g2, EntityType::VULNERABILITY);
    showByType(g2, EntityType::ATTACK_PATTERN);
    showByType(g2, EntityType::IDENTITY);
    showByType(g2, EntityType::TOOL);

    // ---- Step 5: verify neighbours are preserved ----
    printf("\nPasso 5 — Verificar vizinhos de apt29 apos recarregar\n");
    showNeighbours(g2, "apt29");

    // ---- Step 6: verify properties survived the round-trip ----
    printf("\nPasso 6 — Verificar propriedades de nos apos recarregar\n");
    const Node* apt29 = g2.getNode("apt29");
    if (apt29) {
        for (const auto& kv : apt29->properties)
            printf("  apt29.%s = \"%s\"\n", kv.first.c_str(), kv.second.c_str());
    }

    // ---- Step 7: DB-level search demo ----
    showDBSearchDemo(db);

    printf("\n---\nExecucao concluida. Use '--testes' para correr os testes.\n");
    return 0;
}
