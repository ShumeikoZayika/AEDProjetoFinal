#include <cstdio>
#include <cstring>
#include "src/graph.h"
#include "src/synthetic_data.h"
#include "src/tests.h"

// Print the neighbours of a node with full edge info
static void showNeighbours(const Graph& g, const std::string& id) {
    const Node* node = g.getNode(id);
    if (!node) {
        printf("  [!] Nó \"%s\" não encontrado.\n", id.c_str());
        return;
    }
    printf("  Vizinhos de [%s] \"%s\":\n", id.c_str(), node->label.c_str());

    auto edges = g.getOutEdges(id);
    if (edges.empty()) {
        printf("    (nenhum)\n");
        return;
    }
    for (const auto* e : edges) {
        const Node* tgt = g.getNode(e->targetId);
        printf("    --%s--> [%s] \"%s\" (%s)",
               relationTypeToString(e->relation).c_str(),
               e->targetId.c_str(),
               tgt ? tgt->label.c_str() : "?",
               tgt ? entityTypeToString(tgt->type).c_str() : "?");
        if (!e->description.empty())
            printf("  // %s", e->description.c_str());
        printf("\n");
    }
}

// Print all nodes of a given type
static void showNodesByType(const Graph& g, EntityType type) {
    auto nodes = g.getNodesByType(type);
    printf("  Tipo [%s]  (%zu nós):\n", entityTypeToString(type).c_str(), nodes.size());
    for (const auto* n : nodes)
        printf("    [%s] \"%s\"\n", n->id.c_str(), n->label.c_str());
}

// Demonstrate a CTI investigation scenario
static void demonstrateScenario(const Graph& g) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║      Cenário: Investigação de um Indicador Suspeito      ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");
    printf("\n");
    printf("Passo 1 — Foi detetado um hash suspeito nos logs:\n");
    printf("  ioc-hash-sunburst: 32519b85c0b422e4656de6e6c41878e95fd95026...\n\n");

    printf("Passo 2 — O indicador aponta para que malware?\n");
    showNeighbours(g, "ioc-hash-sunburst");
    printf("\n");

    printf("Passo 3 — Que outros indicadores apontam para SUNBURST?\n");
    auto indicators = g.getNodesByType(EntityType::INDICATOR);
    for (const auto* ioc : indicators) {
        for (const auto* nb : g.getNeighbours(ioc->id)) {
            if (nb->id == "sunburst") {
                printf("  [%s] \"%s\" -indicates-> SUNBURST\n",
                       ioc->id.c_str(), ioc->label.c_str());
            }
        }
    }
    printf("\n");

    printf("Passo 4 — Que actor está associado ao SUNBURST?\n");
    showNeighbours(g, "apt29");
    printf("\n");

    printf("Passo 5 — Que técnicas de ataque usa o SUNBURST?\n");
    showNeighbours(g, "sunburst");
    printf("\n");

    printf("Passo 6 — Que organismos são alvos desta campanha?\n");
    showNeighbours(g, "camp-solarwinds");
    printf("\n");
    printf("Conclusão: O hash pertence ao SUNBURST, utilizado pelo APT29\n");
    printf("(Cozy Bear), numa campanha que comprometeu agências do governo\n");
    printf("norte-americano através de uma supply-chain no SolarWinds Orion.\n");
}

int main(int argc, char* argv[]) {
    // Run tests if "--testes" flag is passed
    if (argc > 1 && strcmp(argv[1], "--testes") == 0) {
        return runTests();
    }

    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║   Grafo de Conhecimento - Cyber Threat Intelligence      ║\n");
    printf("║   Nível 1 — Grafo em Memória                             ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");

    // Build graph with synthetic data
    Graph g;
    loadSyntheticData(g);

    printf("Dataset sintético carregado: %d nós, %d relações\n\n",
           g.nodeCount(), g.edgeCount());

    // Show graph statistics by entity type
    printf("=== Entidades por tipo ===\n");
    showNodesByType(g, EntityType::THREAT_ACTOR);
    showNodesByType(g, EntityType::MALWARE);
    showNodesByType(g, EntityType::TOOL);
    showNodesByType(g, EntityType::INDICATOR);
    showNodesByType(g, EntityType::CAMPAIGN);
    showNodesByType(g, EntityType::VULNERABILITY);
    showNodesByType(g, EntityType::ATTACK_PATTERN);
    showNodesByType(g, EntityType::IDENTITY);

    // Show neighbours of a few key nodes
    printf("\n=== Vizinhos de nós seleccionados ===\n");
    showNeighbours(g, "apt29");
    printf("\n");
    showNeighbours(g, "lazarus");
    printf("\n");
    showNeighbours(g, "wannacry");

    // Run the CTI investigation scenario
    demonstrateScenario(g);

    printf("\n---\nExecução concluída. Use '--testes' para correr os testes.\n");
    return 0;
}
