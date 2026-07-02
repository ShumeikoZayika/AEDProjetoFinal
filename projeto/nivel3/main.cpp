#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include "src/graph.h"
#include "src/synthetic_data.h"
#include "src/database.h"
#include "src/algorithms.h"
#include "src/tests.h"

static const char* DB_PATH = "cti_graph.db";

// ---- small printing helpers ------------------------------------------------

static std::string labelOf(const Graph& g, const std::string& id) {
    const Node* n = g.getNode(id);
    return n ? n->label : id;
}

static void printList(const Graph& g, const std::vector<std::string>& ids) {
    if (ids.empty()) { printf("    (nenhum)\n"); return; }
    for (const auto& id : ids)
        printf("    [%s] \"%s\"\n", id.c_str(), labelOf(g, id).c_str());
}

static void printPath(const std::vector<std::string>& path) {
    if (path.empty()) { printf("    (sem caminho)\n"); return; }
    printf("    ");
    for (size_t i = 0; i < path.size(); ++i) {
        printf("[%s]", path[i].c_str());
        if (i + 1 < path.size()) printf("  ->  ");
    }
    printf("\n");
}

static void printOrder(const std::vector<std::string>& order) {
    printf("    ");
    for (size_t i = 0; i < order.size(); ++i) {
        printf("%s", order[i].c_str());
        if (i + 1 < order.size()) printf(" -> ");
    }
    printf("\n");
}

// ---- demo sections ---------------------------------------------------------

static void demoTraversals(const Graph& g) {
    printf("\n=== 1. Travessias (BFS / DFS) a partir de apt29 ===\n");

    printf("\n  BFS (dirigido):\n");
    printOrder(Algorithms::bfs(g, "apt29", true));

    printf("\n  DFS (dirigido):\n");
    printOrder(Algorithms::dfs(g, "apt29", true));
}

static void demoShortestPath(const Graph& g) {
    printf("\n=== 2. Caminho mais curto ===\n");

    printf("\n  Caminho entre o indicador 'ioc-hash-sunburst' e o ator 'apt29':\n");
    printPath(Algorithms::shortestPath(g, "ioc-hash-sunburst", "apt29"));

    printf("\n  Caminho entre o indicador 'ioc-ip-91' e o alvo 'id-nato':\n");
    printPath(Algorithms::shortestPath(g, "ioc-ip-91", "id-nato"));

    printf("\n  Caminho entre 'ioc-hash-wannacry' e 'vuln-ms17-010':\n");
    printPath(Algorithms::shortestPath(g, "ioc-hash-wannacry", "vuln-ms17-010"));
}

static void demoPageRank(const Graph& g) {
    printf("\n=== 3. PageRank — entidades mais relevantes ===\n\n");
    auto ranked = Algorithms::rankEntities(g);

    printf("    %-4s %-22s %-14s %s\n", "#", "id", "score", "tipo");
    printf("    ------------------------------------------------------------\n");
    int rankPos = 1;
    for (const auto& kv : ranked) {
        if (rankPos > 8) break;   // top 8
        const Node* n = g.getNode(kv.first);
        printf("    %-4d %-22s %-14.6f %s\n",
               rankPos++, kv.first.c_str(), kv.second,
               n ? entityTypeToString(n->type).c_str() : "?");
    }
}

static void demoDegreeCentrality(const Graph& g) {
    printf("\n=== 3b. Centralidade por grau (entrada / saida / total) ===\n\n");
    auto dc = Algorithms::degreeCentrality(g);
    printf("    %-4s %-22s %-6s %-6s %-6s %s\n", "#", "id", "entr.", "saida", "total", "tipo");
    printf("    --------------------------------------------------------------\n");
    int pos = 1;
    for (const auto& d : dc) {
        if (pos > 8) break;   // top 8
        const Node* n = g.getNode(d.id);
        printf("    %-4d %-22s %-6d %-6d %-6d %s\n",
               pos++, d.id.c_str(), d.in, d.out, d.total,
               n ? entityTypeToString(n->type).c_str() : "?");
    }
}

static void demoInverseAdjacency(const Graph& g) {
    printf("\n=== 1b. Lista de adjacencia inversa (relacoes de entrada) ===\n");
    printf("\n  Quem aponta para o malware 'sunburst' (vizinhos de entrada)?\n");
    for (const Edge* e : g.getInEdges("sunburst")) {
        const Node* src = g.getNode(e->sourceId);
        printf("    [%s] \"%s\" --%s-->\n",
               e->sourceId.c_str(), src ? src->label.c_str() : "?",
               relationTypeToString(e->relation).c_str());
    }
    printf("\n  Vizinhos de 'sunburst' em ambas as direcoes (entrada+saida):\n");
    for (const Node* n : g.getNeighbours("sunburst", Direction::BOTH))
        printf("    [%s] \"%s\"\n", n->id.c_str(), n->label.c_str());
}

static void demoEntityResolution(const Graph& g) {
    printf("\n=== 4. Resolucao de entidades ===\n");

    printf("\n  resolveByName(\"APT29\"):\n");
    printList(g, Algorithms::resolveByName(g, "APT29"));

    printf("\n  resolveByName(\"Cozy Bear\"):\n");
    printList(g, Algorithms::resolveByName(g, "Cozy Bear"));

    printf("\n  => 'APT29' e 'Cozy Bear' resolvem para o mesmo ator (apt29).\n");

    printf("\n  Potenciais duplicados detetados no grafo:\n");
    auto dups = Algorithms::findPotentialDuplicates(g);
    if (dups.empty()) { printf("    (nenhum)\n"); }
    for (const auto& group : dups) {
        printf("    { ");
        for (size_t i = 0; i < group.size(); ++i) {
            printf("%s", group[i].c_str());
            if (i + 1 < group.size()) printf(", ");
        }
        printf(" }\n");
        for (const auto& id : group)
            printf("        [%s] \"%s\"\n", id.c_str(), labelOf(g, id).c_str());
    }
}

static void demoAnalyticalQueries(const Graph& g) {
    printf("\n=== 5. Consultas analiticas ===\n");

    printf("\n  Que atores usam o malware 'sunburst'?\n");
    printList(g, Algorithms::actorsUsingMalware(g, "sunburst"));

    printf("\n  Que indicadores apontam para 'sunburst'?\n");
    printList(g, Algorithms::indicatorsForThreat(g, "sunburst"));

    printf("\n  Que atores usam o malware 'wannacry'?\n");
    printList(g, Algorithms::actorsUsingMalware(g, "wannacry"));
}

// CTI narrative: from a suspicious indicator to the responsible actor.
static void demoScenario(const Graph& g) {
    printf("\n");
    printf("=== 6. Cenario: do indicador suspeito ao ator ===\n\n");
    printf("  Indicador detetado: ioc-hash-sunburst\n");

    printf("  -> aponta para o malware: sunburst (\"%s\")\n",
           labelOf(g, "sunburst").c_str());

    auto actors = Algorithms::actorsUsingMalware(g, "sunburst");
    printf("  -> usado pelos atores: ");
    for (size_t i = 0; i < actors.size(); ++i)
        printf("%s%s", actors[i].c_str(), (i + 1 < actors.size()) ? ", " : "");
    printf("\n");

    printf("  -> caminho que justifica a ligacao indicador -> ator:\n");
    printPath(Algorithms::shortestPath(g, "ioc-hash-sunburst", "apt29"));

    auto dups = Algorithms::findPotentialDuplicates(g);
    for (const auto& group : dups) {
        bool hasApt29 = false, hasDukes = false;
        for (const auto& id : group) {
            if (id == "apt29") hasApt29 = true;
            if (id == "dukes") hasDukes = true;
        }
        if (hasApt29 && hasDukes) {
            printf("  -> NOTA: 'apt29' e 'dukes' sao o mesmo ator (resolucao de entidades).\n");
            break;
        }
    }

    printf("\n  Conclusao: o hash pertence ao SUNBURST, usado pelo APT29 (Cozy Bear),\n");
    printf("  reportado tambem como 'The Dukes' por outra fonte.\n");
}

int main(int argc, char* argv[]) {
    if (argc > 1 && strcmp(argv[1], "--testes") == 0)
        return runTests();

    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║   Grafo de Conhecimento - Cyber Threat Intelligence      ║\n");
    printf("║   Nível 3 — Algoritmos de Análise                        ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");

    // Build the graph (in memory) and persist it (reuse Level 2 layer)
    Graph g;
    loadSyntheticData(g);
    printf("Dataset sintetico: %d nos, %d relacoes\n", g.nodeCount(), g.edgeCount());

    Database db;
    if (db.initDB(DB_PATH) && db.saveGraph(g))
        printf("Grafo persistido em '%s'.\n", DB_PATH);

    // Run all Level 3 algorithm demonstrations
    demoTraversals(g);
    demoInverseAdjacency(g);
    demoShortestPath(g);
    demoPageRank(g);
    demoDegreeCentrality(g);
    demoEntityResolution(g);
    demoAnalyticalQueries(g);
    demoScenario(g);

    printf("\n---\nExecucao concluida. Use '--testes' para correr os testes.\n");
    return 0;
}
