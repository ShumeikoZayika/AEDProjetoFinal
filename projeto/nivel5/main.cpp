#include <cstdio>
#include <cstring>
#include <string>
#include <sstream>
#include <iostream>
#include "src/graph.h"
#include "src/synthetic_data.h"
#include "src/database.h"
#include "src/algorithms.h"
#include "src/service.h"
#include "src/gui.h"
#include "src/tests.h"

static const char* DB_PATH = "cti_graph.db";

// ---- printing helpers ------------------------------------------------------

static void printHelp() {
    printf("\nComandos disponiveis (menu local / camada de servicos):\n");
    printf("  help                          mostra esta ajuda\n");
    printf("  stats                         estatisticas gerais do grafo\n");
    printf("  nodes <tipo>                  lista nos de um tipo\n");
    printf("  node <id>                     mostra um no e os seus detalhes\n");
    printf("  addnode <id> <tipo> <label>   cria um no (com validacao)\n");
    printf("  addedge <orig> <dest> <rel>   cria uma relacao (com validacao)\n");
    printf("  neighbours <id> [out|in|both] vizinhos de um no (default out)\n");
    printf("  path <orig> <dest>            caminho mais curto (BFS)\n");
    printf("  ranking                       entidades mais relevantes (PageRank)\n");
    printf("  degree                        centralidade por grau (in/out/total)\n");
    printf("  gui                           abre a interface grafica (janela raylib)\n");
    printf("  save                          guarda o grafo na base de dados\n");
    printf("  reload                        recarrega o grafo da base de dados\n");
    printf("  quit                          sair\n");
    printf("  (tipos: threat-actor malware indicator campaign vulnerability\n");
    printf("          identity attack-pattern tool)\n\n");
}

static void printNodeDetails(const Service& svc, const Node* n) {
    printf("  [%s] \"%s\"  (tipo: %s)\n", n->id.c_str(), n->label.c_str(),
           entityTypeToString(n->type).c_str());
    for (const auto& kv : n->properties)
        printf("    %s: %s\n", kv.first.c_str(), kv.second.c_str());
    (void)svc;
}

static void printResult(const OpResult& r) {
    if (r.ok) printf("  OK: %s\n", r.message.c_str());
    else      printf("  ERRO: %s\n", r.message.c_str());
}

// ---- command dispatch ------------------------------------------------------

// Returns false when the user asks to quit.
static bool handleCommand(Service& svc, Graph& g, const std::string& line) {
    std::istringstream iss(line);
    std::string cmd;
    if (!(iss >> cmd)) return true;   // empty line

    if (cmd == "quit" || cmd == "exit" || cmd == "q") {
        printf("  A terminar.\n");
        return false;
    }
    if (cmd == "help") { printHelp(); return true; }

    if (cmd == "stats") {
        auto s = svc.stats();
        printf("  Nos: %d   Relacoes: %d\n", s.nodes, s.edges);
        printf("  Por tipo:\n");
        for (const auto& kv : s.nodesByType)
            printf("    %-15s %d\n", kv.first.c_str(), kv.second);
        printf("  Mais relevante (PageRank): %s\n", s.topByPageRank.c_str());
        printf("  Maior grau:                %s\n", s.topByDegree.c_str());
        return true;
    }
    if (cmd == "nodes") {
        std::string type; iss >> type;
        if (type.empty()) { printf("  ERRO: indique um tipo. Ex: nodes malware\n"); return true; }
        bool valid;
        auto nodes = svc.listNodesByType(type, valid);
        if (!valid) { printf("  ERRO: tipo invalido '%s'.\n", type.c_str()); return true; }
        printf("  %zu no(s) do tipo '%s':\n", nodes.size(), type.c_str());
        for (const Node* n : nodes)
            printf("    [%s] \"%s\"\n", n->id.c_str(), n->label.c_str());
        return true;
    }
    if (cmd == "node") {
        std::string id; iss >> id;
        const Node* n = svc.getNode(id);
        if (!n) { printf("  ERRO: no '%s' nao existe.\n", id.c_str()); return true; }
        printNodeDetails(svc, n);
        return true;
    }
    if (cmd == "addnode") {
        std::string id, type, label, w;
        iss >> id >> type;
        std::getline(iss, label);
        // trim leading space of label
        size_t p = label.find_first_not_of(' ');
        label = (p == std::string::npos) ? "" : label.substr(p);
        printResult(svc.createNode(id, label, type));
        return true;
    }
    if (cmd == "addedge") {
        std::string s, t, r; iss >> s >> t >> r;
        printResult(svc.createEdge(s, t, r));
        return true;
    }
    if (cmd == "neighbours" || cmd == "vizinhos") {
        std::string id, dir; iss >> id >> dir;
        std::vector<const Node*> out;
        OpResult r = svc.neighbours(id, dir, out);
        if (!r.ok) { printf("  ERRO: %s\n", r.message.c_str()); return true; }
        printf("  Vizinhos de '%s' (%s):\n", id.c_str(), dir.empty() ? "out" : dir.c_str());
        if (out.empty()) printf("    (nenhum)\n");
        for (const Node* n : out)
            printf("    [%s] \"%s\" (%s)\n", n->id.c_str(), n->label.c_str(),
                   entityTypeToString(n->type).c_str());
        return true;
    }
    if (cmd == "path") {
        std::string s, t; iss >> s >> t;
        std::vector<std::string> path;
        OpResult r = svc.shortestPath(s, t, path);
        if (!r.ok) { printf("  ERRO: %s\n", r.message.c_str()); return true; }
        printf("  Caminho mais curto:\n    ");
        for (size_t i = 0; i < path.size(); ++i)
            printf("%s%s", path[i].c_str(), (i + 1 < path.size()) ? "  ->  " : "\n");
        return true;
    }
    if (cmd == "ranking") {
        auto r = svc.ranking();
        printf("  Top entidades (PageRank):\n");
        int pos = 1;
        for (const auto& kv : r) { if (pos > 8) break;
            printf("    %2d. %-22s %.6f\n", pos++, kv.first.c_str(), kv.second); }
        return true;
    }
    if (cmd == "degree") {
        auto d = svc.degreeRanking();
        printf("  Centralidade por grau (entrada/saida/total):\n");
        int pos = 1;
        for (const auto& dc : d) { if (pos > 8) break;
            printf("    %2d. %-22s in=%-3d out=%-3d total=%-3d\n",
                   pos++, dc.id.c_str(), dc.in, dc.out, dc.total); }
        return true;
    }
    if (cmd == "gui" || cmd == "viz") {
        printf("  A abrir a janela grafica (feche-a para voltar ao menu)...\n");
        Gui::run(svc, g);
        return true;
    }
    if (cmd == "save")   { printResult(svc.save());   return true; }
    if (cmd == "reload") { printResult(svc.reload()); return true; }

    printf("  Comando desconhecido: '%s'. Escreva 'help'.\n", cmd.c_str());
    return true;
}

// ---- scripted demonstration (non-interactive) ------------------------------

static void runDemo(Service& svc, Graph& g) {
    const char* script[] = {
        "stats",
        "nodes threat-actor",
        "node apt29",
        "neighbours sunburst in",
        "neighbours apt29 both",
        "path ioc-hash-sunburst apt29",
        "ranking",
        "degree",
        // --- validation / error handling ---
        "addnode apt29 threat-actor APT29 duplicado",     // duplicado -> erro
        "addnode evilcorp threat-actor Evil Corp",         // valido
        "addedge evilcorp wannacry uses",                  // valido
        "addedge wannacry evilcorp targets",               // relacao invalida -> erro
        "addedge evilcorp inexistente uses",               // destino inexistente -> erro
        "node fantasma",                                   // no inexistente -> erro
        "path apt29 lazarus",                              // sem caminho (dirigido) -> erro
        "neighbours apt29 lateral",                        // direcao invalida -> erro
    };
    for (const char* c : script) {
        printf("\n> %s\n", c);
        handleCommand(svc, g, c);
    }
}

// ---- entry point -----------------------------------------------------------

int main(int argc, char* argv[]) {
    if (argc > 1 && strcmp(argv[1], "--testes") == 0)
        return runTests();

    printf("==================================================================\n");
    printf("  Grafo de Conhecimento CTI - Nivel 5 (Interface grafica + menu)\n");
    printf("==================================================================\n");

    Graph g;
    Database db;
    bool dbOk = db.initDB(DB_PATH);
    bool fromDb = false;
    if (dbOk && db.loadGraph(g) && g.nodeCount() > 0) {
        // A base de dados já tem dados de sessões anteriores: usa-os,
        // em vez de os substituir pelos dados sintéticos.
        fromDb = true;
    } else {
        // Primeira execução (ou BD vazia): povoa com dados sintéticos.
        g.clear();
        loadSyntheticData(g);
        if (dbOk) dbOk = db.saveGraph(g);
    }
    Service svc(g, dbOk ? &db : nullptr);
    printf("Grafo carregado: %d nos, %d relacoes%s\n",
           g.nodeCount(), g.edgeCount(),
           !dbOk ? " (sem persistencia)"
                 : (fromDb ? " (carregado da base de dados)"
                           : " (dados sinteticos, persistido)"));

    // Scripted text demonstration of the service layer (Nível 4).
    if (argc > 1 && strcmp(argv[1], "--demo") == 0) {
        runDemo(svc, g);
        printf("\nDemonstracao concluida.\n");
        return 0;
    }

    // Text menu (REPL) — same operations as Nível 4.
    if (argc > 1 && strcmp(argv[1], "--menu") == 0) {
        printHelp();
        std::string line;
        printf("> ");
        while (std::getline(std::cin, line)) {
            if (!handleCommand(svc, g, line)) break;
            printf("> ");
        }
        return 0;
    }

    // Default: open the native graphical interface (raylib).
    printf("A abrir a interface grafica (feche a janela para sair).\n");
    printf("Use './cti_graph --menu' para o menu de texto, '--testes' para os testes.\n");
    Gui::run(svc, g);
    return 0;
}
