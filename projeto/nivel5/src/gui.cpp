#include "gui.h"
#include "algorithms.h"
#include <raylib.h>
#include <map>
#include <set>
#include <vector>
#include <string>
#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <cstdio>

namespace Gui {

// ---- layout constants ------------------------------------------------------
static const int   WIN_W = 1240, WIN_H = 860;
static const int   PANEL_W = 340;
static const float GRAPH_W = WIN_W - PANEL_W;

static const Color BG       = (Color){ 15, 20, 33, 255 };
static const Color PANEL_BG = (Color){ 21, 27, 43, 255 };
static const Color ACCENT   = (Color){ 127, 176, 255, 255 };
static const Color EDGE_COL = (Color){ 70, 84, 112, 255 };
static const Color LABEL_BG = (Color){ 0, 0, 0, 175 };
static const Color TXT      = (Color){ 225, 232, 245, 255 };
static const Color FIELD_BG = (Color){ 15, 20, 33, 255 };
static const Color OKGREEN  = (Color){ 120, 200, 120, 255 };
static const Color ERRRED   = (Color){ 240, 120, 110, 255 };

static Font  g_font;
static float g_spacing = 1.0f;
static float TW(const char* s, float fs) { return MeasureTextEx(g_font, s, fs, g_spacing).x; }
static void  TX(const char* s, float x, float y, float fs, Color c) {
    DrawTextEx(g_font, s, (Vector2){ x, y }, fs, g_spacing, c);
}
static void drawLabel(const char* text, float cx, float topY, float fs, Color txt) {
    float w = TW(text, fs);
    Rectangle pill = { cx - w / 2.0f - 5, topY - 2, w + 10, fs + 6 };
    DrawRectangleRounded(pill, 0.5f, 6, LABEL_BG);
    TX(text, cx - w / 2.0f, topY, fs, txt);
}

static Color typeColor(EntityType t) {
    switch (t) {
        case EntityType::THREAT_ACTOR:   return (Color){225, 87, 89, 255};
        case EntityType::MALWARE:        return (Color){242, 142, 43, 255};
        case EntityType::INDICATOR:      return (Color){78, 121, 167, 255};
        case EntityType::CAMPAIGN:       return (Color){176, 122, 161, 255};
        case EntityType::VULNERABILITY:  return (Color){237, 201, 72, 255};
        case EntityType::IDENTITY:       return (Color){118, 183, 178, 255};
        case EntityType::ATTACK_PATTERN: return (Color){89, 161, 79, 255};
        case EntityType::TOOL:           return (Color){156, 117, 95, 255};
        default:                         return (Color){136, 136, 136, 255};
    }
}

struct NodeVis {
    std::string id, label;
    EntityType  type;
    Vector2 pos, vel;
    float   radius;
    int     indeg, outdeg;
    double  pr;
};

static float frand(float a, float b) { return a + (b - a) * ((float)rand() / (float)RAND_MAX); }

static bool loadUiFont() {
    const char* candidates[] = {
        "/System/Library/Fonts/Supplemental/Arial.ttf",
        "/System/Library/Fonts/Supplemental/Verdana.ttf",
        "/System/Library/Fonts/SFNS.ttf",
        "/System/Library/Fonts/Helvetica.ttc",
        "/Library/Fonts/Arial.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "C:/Windows/Fonts/segoeui.ttf",
    };
    for (const char* c : candidates)
        if (FileExists(c)) {
            g_font = LoadFontEx(c, 64, nullptr, 0);
            if (g_font.texture.id != 0) { SetTextureFilter(g_font.texture, TEXTURE_FILTER_BILINEAR); return true; }
        }
    g_font = GetFontDefault();
    return false;
}

// small reusable button; returns true if clicked this frame
static bool button(Rectangle r, const char* lbl, Vector2 mouse, bool enabled = true, bool on = false) {
    bool hov = enabled && CheckCollisionPointRec(mouse, r);
    Color bgc = on ? (Color){ 46, 84, 150, 255 }
                   : (hov ? (Color){ 60, 72, 104, 255 } : (Color){ 40, 48, 70, 255 });
    if (!enabled) bgc = (Color){ 30, 36, 52, 255 };
    DrawRectangleRounded(r, 0.3f, 6, bgc);
    TX(lbl, r.x + (r.width - TW(lbl, 14)) / 2, r.y + (r.height - 14) / 2, 14, enabled ? WHITE : GRAY);
    return hov && IsMouseButtonPressed(MOUSE_BUTTON_LEFT);
}

void run(Service& svc, Graph& g) {
    static const std::vector<std::string> TYPES = {
        "threat-actor","malware","indicator","campaign",
        "vulnerability","identity","attack-pattern","tool" };
    static const std::vector<std::string> RELS = {
        "uses","indicates","targets","exploits",
        "attributed-to","part-of","drops","delivers" };

    std::vector<NodeVis> nodes;
    std::map<std::string, int> idx;
    std::vector<std::string> idList;      // sorted ids, for selection menus
    struct E { int a, b; std::string rel; };
    std::vector<E> edges;
    std::map<std::string, double> prMap;
    double maxPr = 1.0;

    int selected = -1, pathDst = -1, dragging = -1;
    std::vector<std::string> path;
    std::set<std::string> pathNodes;
    std::set<long long> pathEdges;
    std::set<int> neighbourSet;

    auto rebuild = [&](bool keepPositions) {
        std::map<std::string, Vector2> old;
        if (keepPositions) for (auto& nv : nodes) old[nv.id] = nv.pos;
        prMap = Algorithms::pageRank(g);
        maxPr = 0.0;
        for (auto& kv : prMap) if (kv.second > maxPr) maxPr = kv.second;
        if (maxPr <= 0.0) maxPr = 1.0;
        nodes.clear(); idx.clear(); idList.clear();
        for (const Node* n : g.getAllNodes()) {
            NodeVis nv;
            nv.id = n->id; nv.label = n->label; nv.type = n->type;
            nv.pr = prMap.count(n->id) ? prMap[n->id] : 0.0;
            nv.radius = 10.0f + 28.0f * (float)(nv.pr / maxPr);
            nv.indeg = g.inDegree(n->id); nv.outdeg = g.outDegree(n->id);
            nv.pos = old.count(n->id) ? old[n->id]
                                      : (Vector2){ frand(120, GRAPH_W - 120), frand(120, WIN_H - 120) };
            nv.vel = (Vector2){ 0, 0 };
            idx[n->id] = (int)nodes.size();
            nodes.push_back(nv);
            idList.push_back(n->id);
        }
        std::sort(idList.begin(), idList.end());
        edges.clear();
        for (const Edge* e : g.getAllEdges())
            if (idx.count(e->sourceId) && idx.count(e->targetId))
                edges.push_back({ idx[e->sourceId], idx[e->targetId], relationTypeToString(e->relation) });
        selected = pathDst = dragging = -1;
        path.clear(); pathNodes.clear(); pathEdges.clear(); neighbourSet.clear();
    };

    std::set<int> activeTypes;
    std::vector<EntityType> legendTypes = {
        EntityType::THREAT_ACTOR, EntityType::MALWARE, EntityType::INDICATOR,
        EntityType::CAMPAIGN, EntityType::VULNERABILITY, EntityType::IDENTITY,
        EntityType::ATTACK_PATTERN, EntityType::TOOL };
    for (auto tt : legendTypes) activeTypes.insert((int)tt);
    auto visible = [&](const NodeVis& n) { return activeTypes.count((int)n.type) > 0; };

    auto rebuildNeighbours = [&]() {
        neighbourSet.clear();
        if (selected < 0) return;
        for (const Node* n : g.getNeighbours(nodes[selected].id, Direction::BOTH))
            if (idx.count(n->id)) neighbourSet.insert(idx[n->id]);
    };
    auto recomputePath = [&]() {
        path.clear(); pathNodes.clear(); pathEdges.clear();
        if (selected < 0 || pathDst < 0) return;
        path = Algorithms::shortestPath(g, nodes[selected].id, nodes[pathDst].id);
        for (auto& id : path) pathNodes.insert(id);
        for (size_t i = 1; i < path.size(); ++i) {
            int a = idx[path[i - 1]], b = idx[path[i]];
            pathEdges.insert((long long)a * 100000 + b);
            pathEdges.insert((long long)b * 100000 + a);
        }
    };
    auto listIndexOf = [&](const std::string& id) {
        auto it = std::find(idList.begin(), idList.end(), id);
        return it == idList.end() ? 0 : (int)(it - idList.begin());
    };

    // form state
    int formMode = 0;                       // 0 none, 1 add node, 2 add edge
    int nField = 0, nTypeIdx = 0;           // node form: field(0 id,1 label), type
    std::string nId, nLabel;
    int eField = 0, eSrcIdx = 0, eTgtIdx = 0, eRelIdx = 0;  // edge form
    std::string msg; Color msgCol = TXT;
    bool layoutOn = true, showDegree = false;
    bool searchActive = false; std::string searchText;
    Vector2 pressPos = { 0, 0 }; bool pressEmpty = false;   // clique vazio = desselecionar
    // análise (Nível 3) + listagem por tipo (Nível 4)
    bool showDups = false;
    std::set<std::string> dupNodes;
    std::vector<std::vector<std::string>> dupGroups;
    std::vector<std::string> travOrder;
    std::map<std::string, int> travIndex;
    std::string travMode;
    int listType = -1;   // EntityType (int) a listar no painel; -1 = nenhum
    int scenStep = 0;    // cenario narrativo guiado (0 = inativo, 1..4)
    // "entidade mais provavel" (form mode 4)
    int pField = 0, pSrcIdx = 0, pTypeIdx = 0;
    std::vector<Algorithms::ProbCandidate> probCands;
    std::string probSrcId; int probTypeShown = -1;

    Camera2D cam;
    cam.offset = (Vector2){ GRAPH_W / 2, WIN_H / 2 };
    cam.target = (Vector2){ GRAPH_W / 2, WIN_H / 2 };
    cam.rotation = 0.0f; cam.zoom = 1.0f;

    auto flushChars = []() { while (GetCharPressed() > 0) {} };  // avoid hotkey leaking into field
    auto openAddNode = [&]() { formMode = 1; nId = ""; nLabel = ""; nTypeIdx = 0; nField = 0; msg = ""; flushChars(); };
    auto openEdgeForm = [&](int mode) {
        formMode = mode; eField = 0; eRelIdx = 0; msg = "";
        eSrcIdx = (selected >= 0) ? listIndexOf(nodes[selected].id) : 0;
        eTgtIdx = (pathDst  >= 0) ? listIndexOf(nodes[pathDst].id)  : (idList.size() > 1 ? 1 : 0);
        flushChars();
    };
    auto openAddEdge = [&]() { openEdgeForm(2); };
    auto openDelEdge = [&]() { openEdgeForm(3); };
    auto openProbable = [&]() {
        formMode = 4; pField = 0; pTypeIdx = 0; msg = "";
        pSrcIdx = (selected >= 0) ? listIndexOf(nodes[selected].id) : 0;
        flushChars();
    };
    auto deleteSelected = [&]() {
        if (selected < 0) { msg = "Selecione um no primeiro."; msgCol = ERRRED; return; }
        OpResult r = svc.deleteNode(nodes[selected].id);
        msg = r.message; msgCol = r.ok ? OKGREEN : ERRRED;
        if (r.ok) rebuild(true);
    };
    auto submitForm = [&]() {
        if (formMode == 4) {   // calcular entidade mais provavel
            probSrcId = idList.empty() ? "" : idList[pSrcIdx];
            EntityType ty = stringToEntityType(TYPES[pTypeIdx]);
            probTypeShown = (int)ty;
            probCands = Algorithms::mostProbable(g, probSrcId, ty);
            if (probCands.empty()) { msg = "Sem candidatos do tipo " + TYPES[pTypeIdx]; msgCol = ERRRED; }
            else {
                const std::string best = probCands.front().id;
                if (idx.count(probSrcId)) selected = idx[probSrcId];
                if (idx.count(best)) {
                    pathDst = idx[best]; rebuildNeighbours(); recomputePath();
                    cam.target = nodes[idx[best]].pos; cam.offset = (Vector2){ GRAPH_W / 2, WIN_H / 2 };
                }
                msg = "Mais provavel: " + best; msgCol = OKGREEN;
            }
            formMode = 0; return;
        }
        OpResult r;
        std::string s = idList.empty() ? "" : idList[eSrcIdx];
        std::string t = idList.empty() ? "" : idList[eTgtIdx];
        if (formMode == 1)      r = svc.createNode(nId, nLabel, TYPES[nTypeIdx]);
        else if (formMode == 2) r = svc.createEdge(s, t, RELS[eRelIdx]);
        else                    r = svc.deleteEdge(s, t, RELS[eRelIdx]);   // mode 3
        msg = r.message; msgCol = r.ok ? OKGREEN : ERRRED;
        if (r.ok) { rebuild(true); formMode = 0; }
    };

    // Procurar um nó pelo id (acesso O(log V) por identificador) e centrá-lo.
    auto doSearch = [&]() {
        if (searchText.empty()) return;
        const Node* n = svc.getNode(searchText);          // lookup por id no mapa
        if (n && idx.count(searchText)) {
            selected = idx[searchText]; pathDst = -1;
            rebuildNeighbours(); recomputePath();
            cam.target = nodes[selected].pos;
            cam.offset = (Vector2){ GRAPH_W / 2, WIN_H / 2 };
            msg = "Encontrado: " + searchText; msgCol = OKGREEN;
        } else {
            msg = "id '" + searchText + "' nao encontrado"; msgCol = ERRRED;
        }
    };

    auto computeDups = [&]() {
        dupGroups = Algorithms::findPotentialDuplicates(g);
        dupNodes.clear();
        for (auto& grp : dupGroups) for (auto& id : grp) dupNodes.insert(id);
    };
    auto runTraversal = [&](bool bfs) {
        travOrder.clear(); travIndex.clear(); travMode = "";
        if (selected < 0) { msg = "Selecione um no primeiro."; msgCol = ERRRED; return; }
        travOrder = bfs ? Algorithms::bfs(g, nodes[selected].id, true)
                        : Algorithms::dfs(g, nodes[selected].id, true);
        for (size_t i = 0; i < travOrder.size(); ++i) travIndex[travOrder[i]] = (int)i + 1;
        travMode = bfs ? "BFS" : "DFS";
        msg = travMode + " a partir de " + nodes[selected].id; msgCol = OKGREEN;
    };
    auto clearAnalysis = [&]() {
        showDups = false; dupNodes.clear(); dupGroups.clear();
        travOrder.clear(); travIndex.clear(); travMode = ""; listType = -1;
        scenStep = 0;
        probCands.clear(); probTypeShown = -1;
    };
    // Cenário narrativo guiado: indicador -> malware -> ator -> caminho (BFS).
    auto advanceScenario = [&]() {
        const std::string IND = "ioc-hash-sunburst", MAL = "sunburst", ACT = "apt29";
        if (!g.getNode(IND) || !g.getNode(MAL) || !g.getNode(ACT)) {
            msg = "Cenario indisponivel (dataset alterado)."; msgCol = ERRRED; scenStep = 0; return;
        }
        scenStep = (scenStep % 4) + 1;
        auto centre = [&](const std::string& id) {
            if (idx.count(id)) { selected = idx[id]; rebuildNeighbours();
                cam.target = nodes[selected].pos; cam.offset = (Vector2){ GRAPH_W / 2, WIN_H / 2 }; }
        };
        path.clear(); pathNodes.clear(); pathEdges.clear();
        pathDst = -1;
        if (scenStep == 1)      centre(IND);
        else if (scenStep == 2) centre(MAL);
        else if (scenStep == 3) centre(ACT);
        else { selected = idx[IND]; pathDst = idx[ACT]; rebuildNeighbours(); recomputePath();
               cam.target = nodes[selected].pos; cam.offset = (Vector2){ GRAPH_W / 2, WIN_H / 2 }; }
        msg = "Cenario: passo " + std::to_string(scenStep) + "/4"; msgCol = OKGREEN;
    };

    InitWindow(WIN_W, WIN_H, "Grafo de Conhecimento CTI - Nivel 5 (raylib)");
    SetTargetFPS(60);
    SetExitKey(KEY_NULL);     // ESC já não fecha a app — só cancela formulários
    bool customFont = loadUiFont();
    rebuild(false);

    float bx = GRAPH_W + 16, bw = 152, bh = 28, gap = 12, step = bh + 8;
    Rectangle rSearch  = { bx, 70, bw * 2 + gap, bh };          // procurar no por id
    float b0 = 128;                                             // primeira linha de botoes
    Rectangle bNewNode = { bx,            b0,            bw, bh };
    Rectangle bNewEdge = { bx + bw + gap, b0,            bw, bh };
    Rectangle bDelNode = { bx,            b0 + step,     bw, bh };
    Rectangle bDelEdge = { bx + bw + gap, b0 + step,     bw, bh };
    Rectangle bSave    = { bx,            b0 + 2*step,   bw, bh };
    Rectangle bReload  = { bx + bw + gap, b0 + 2*step,   bw, bh };
    Rectangle bBFS     = { bx,            b0 + 3*step,   bw, bh };
    Rectangle bDFS     = { bx + bw + gap, b0 + 3*step,   bw, bh };
    Rectangle bDups    = { bx,            b0 + 4*step,   bw, bh };
    Rectangle bProbable= { bx + bw + gap, b0 + 4*step,   bw, bh };
    Rectangle bScenario= { bx,            b0 + 5*step,   bw * 2 + gap, bh };
    Rectangle bRank    = { bx,            b0 + 6*step,   bw * 2 + gap, bh };

    while (!WindowShouldClose()) {
        Vector2 mouse = GetMousePosition();
        bool inGraph = mouse.x < GRAPH_W;
        Vector2 world = GetScreenToWorld2D(mouse, cam);

        // form geometry (also used for input hit-testing)
        Rectangle box = { GRAPH_W / 2 - 200, 200, 400, 320 };
        float ffx = box.x + 20;
        Rectangle rField0 = { ffx, box.y + 64,  360, 30 };
        Rectangle rField1 = { ffx, box.y + 128, 360, 30 };
        Rectangle rSelPrev = { ffx,        box.y + 192, 30, 30 };
        Rectangle rSelNext = { ffx + 330,  box.y + 192, 30, 30 };
        Rectangle rField0Prev = rField0, rField0Next = rField0; // for edge form rows
        // edge form uses three selector rows
        Rectangle eRow0Prev = { ffx, box.y + 60,  30, 30 }, eRow0Next = { ffx + 330, box.y + 60,  30, 30 };
        Rectangle eRow1Prev = { ffx, box.y + 124, 30, 30 }, eRow1Next = { ffx + 330, box.y + 124, 30, 30 };
        Rectangle eRow2Prev = { ffx, box.y + 188, 30, 30 }, eRow2Next = { ffx + 330, box.y + 188, 30, 30 };
        Rectangle rOK     = { box.x + box.width - 200, box.y + box.height - 46, 88, 32 };
        Rectangle rCancel = { box.x + box.width - 104, box.y + box.height - 46, 88, 32 };
        (void)rField0Prev; (void)rField0Next;

        // ---------------- input ----------------
        if (formMode != 0) {
            // keyboard
            if (formMode == 1) {
                std::string* af = (nField == 0) ? &nId : &nLabel;
                int c = GetCharPressed();
                while (c > 0) { if (c >= 32 && c <= 126 && af->size() < 40) *af += (char)c; c = GetCharPressed(); }
                if (IsKeyPressed(KEY_BACKSPACE) && !af->empty()) af->pop_back();
                if (IsKeyPressed(KEY_TAB)) nField = (nField + 1) % 2;
                if (IsKeyPressed(KEY_DOWN)) nTypeIdx = (nTypeIdx + 1) % (int)TYPES.size();
                if (IsKeyPressed(KEY_UP))   nTypeIdx = (int)((nTypeIdx + TYPES.size() - 1) % TYPES.size());
                // mouse
                if (IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
                    if (CheckCollisionPointRec(mouse, rField0)) nField = 0;
                    else if (CheckCollisionPointRec(mouse, rField1)) nField = 1;
                    else if (CheckCollisionPointRec(mouse, rSelPrev)) nTypeIdx = (int)((nTypeIdx + TYPES.size() - 1) % TYPES.size());
                    else if (CheckCollisionPointRec(mouse, rSelNext)) nTypeIdx = (nTypeIdx + 1) % (int)TYPES.size();
                }
            } else if (formMode == 2 || formMode == 3) {
                if (IsKeyPressed(KEY_TAB)) eField = (eField + 1) % 3;
                int n = (int)idList.size();
                auto cyc = [&](int& v, int mod, int d) { v = ((v + d) % mod + mod) % mod; };
                if (IsKeyPressed(KEY_DOWN) || IsKeyPressed(KEY_RIGHT)) { if (eField==0) cyc(eSrcIdx,n,1); else if (eField==1) cyc(eTgtIdx,n,1); else cyc(eRelIdx,(int)RELS.size(),1); }
                if (IsKeyPressed(KEY_UP)   || IsKeyPressed(KEY_LEFT))  { if (eField==0) cyc(eSrcIdx,n,-1); else if (eField==1) cyc(eTgtIdx,n,-1); else cyc(eRelIdx,(int)RELS.size(),-1); }
                if (IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
                    if (CheckCollisionPointRec(mouse,eRow0Prev)) cyc(eSrcIdx,n,-1);
                    else if (CheckCollisionPointRec(mouse,eRow0Next)) cyc(eSrcIdx,n,1);
                    else if (CheckCollisionPointRec(mouse,eRow1Prev)) cyc(eTgtIdx,n,-1);
                    else if (CheckCollisionPointRec(mouse,eRow1Next)) cyc(eTgtIdx,n,1);
                    else if (CheckCollisionPointRec(mouse,eRow2Prev)) cyc(eRelIdx,(int)RELS.size(),-1);
                    else if (CheckCollisionPointRec(mouse,eRow2Next)) cyc(eRelIdx,(int)RELS.size(),1);
                }
            } else {   // formMode == 4: entidade mais provavel (origem + tipo)
                if (IsKeyPressed(KEY_TAB)) pField = (pField + 1) % 2;
                int n = (int)idList.size();
                auto cyc = [&](int& v, int mod, int d) { v = ((v + d) % mod + mod) % mod; };
                if (IsKeyPressed(KEY_DOWN) || IsKeyPressed(KEY_RIGHT)) { if (pField==0) cyc(pSrcIdx,n,1); else cyc(pTypeIdx,(int)TYPES.size(),1); }
                if (IsKeyPressed(KEY_UP)   || IsKeyPressed(KEY_LEFT))  { if (pField==0) cyc(pSrcIdx,n,-1); else cyc(pTypeIdx,(int)TYPES.size(),-1); }
                if (IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
                    if (CheckCollisionPointRec(mouse,eRow0Prev)) cyc(pSrcIdx,n,-1);
                    else if (CheckCollisionPointRec(mouse,eRow0Next)) cyc(pSrcIdx,n,1);
                    else if (CheckCollisionPointRec(mouse,eRow1Prev)) cyc(pTypeIdx,(int)TYPES.size(),-1);
                    else if (CheckCollisionPointRec(mouse,eRow1Next)) cyc(pTypeIdx,(int)TYPES.size(),1);
                }
            }
            if (IsKeyPressed(KEY_ENTER)) submitForm();
            if (IsKeyPressed(KEY_ESCAPE)) formMode = 0;
            if (IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
                if (CheckCollisionPointRec(mouse, rOK)) submitForm();
                else if (CheckCollisionPointRec(mouse, rCancel)) formMode = 0;
            }
        } else {
            // search box (procurar no por id)
            if (IsMouseButtonPressed(MOUSE_BUTTON_LEFT))
                searchActive = CheckCollisionPointRec(mouse, rSearch);
            if (searchActive) {
                int c = GetCharPressed();
                while (c > 0) { if (c >= 32 && c <= 126 && searchText.size() < 40) searchText += (char)c; c = GetCharPressed(); }
                if (IsKeyPressed(KEY_BACKSPACE) && !searchText.empty()) searchText.pop_back();
                if (IsKeyPressed(KEY_ENTER)) doSearch();
                if (IsKeyPressed(KEY_ESCAPE)) searchActive = false;
            }
            if (layoutOn) {
                for (size_t i = 0; i < nodes.size(); ++i) {
                    if ((int)i == dragging) continue;
                    Vector2 force = { 0, 0 };
                    for (size_t j = 0; j < nodes.size(); ++j) {
                        if (i == j) continue;
                        float dx = nodes[i].pos.x - nodes[j].pos.x;
                        float dy = nodes[i].pos.y - nodes[j].pos.y;
                        float d2 = dx * dx + dy * dy + 0.01f, d = sqrtf(d2), f = 28000.0f / d2;
                        force.x += f * dx / d; force.y += f * dy / d;
                    }
                    force.x += (GRAPH_W / 2 - nodes[i].pos.x) * 0.005f;
                    force.y += (WIN_H / 2 - nodes[i].pos.y) * 0.005f;
                    nodes[i].vel.x = (nodes[i].vel.x + force.x) * 0.85f;
                    nodes[i].vel.y = (nodes[i].vel.y + force.y) * 0.85f;
                }
                for (const E& e : edges) {
                    NodeVis& A = nodes[e.a]; NodeVis& B = nodes[e.b];
                    float dx = B.pos.x - A.pos.x, dy = B.pos.y - A.pos.y;
                    float d = sqrtf(dx * dx + dy * dy) + 0.01f;
                    float k = (d - 180.0f) * 0.02f, fx = k * dx / d, fy = k * dy / d;
                    if (e.a != dragging) { A.vel.x += fx; A.vel.y += fy; }
                    if (e.b != dragging) { B.vel.x -= fx; B.vel.y -= fy; }
                }
                for (size_t i = 0; i < nodes.size(); ++i) {
                    if ((int)i == dragging) continue;
                    nodes[i].pos.x += nodes[i].vel.x * 0.05f;
                    nodes[i].pos.y += nodes[i].vel.y * 0.05f;
                }
            }
            // resolucao de colisoes: garante que as esferas nunca se sobrepoem
            for (size_t i = 0; i < nodes.size(); ++i)
                for (size_t j = i + 1; j < nodes.size(); ++j) {
                    float dx = nodes[j].pos.x - nodes[i].pos.x;
                    float dy = nodes[j].pos.y - nodes[i].pos.y;
                    float d = sqrtf(dx * dx + dy * dy) + 0.001f;
                    float minD = nodes[i].radius + nodes[j].radius + 22.0f;
                    if (d < minD) {
                        float push = (minD - d) * 0.5f, ux = dx / d, uy = dy / d;
                        if ((int)i != dragging) { nodes[i].pos.x -= ux * push; nodes[i].pos.y -= uy * push; }
                        if ((int)j != dragging) { nodes[j].pos.x += ux * push; nodes[j].pos.y += uy * push; }
                    }
                }
            if (!searchActive) {
                if (IsKeyPressed(KEY_SPACE)) layoutOn = !layoutOn;
                if (IsKeyPressed(KEY_R)) { selected = pathDst = -1; path.clear(); pathNodes.clear(); pathEdges.clear(); neighbourSet.clear(); clearAnalysis(); }
                if (IsKeyPressed(KEY_ZERO)) { cam.zoom = 1.0f; cam.target = (Vector2){ GRAPH_W / 2, WIN_H / 2 }; cam.offset = (Vector2){ GRAPH_W / 2, WIN_H / 2 }; }
                if (IsKeyPressed(KEY_N)) openAddNode();
                if (IsKeyPressed(KEY_E)) openAddEdge();
                if (IsKeyPressed(KEY_DELETE)) deleteSelected();
                if (IsKeyPressed(KEY_G)) { OpResult r = svc.save(); msg = r.message; msgCol = r.ok ? OKGREEN : ERRRED; }
            }

            float wheel = GetMouseWheelMove();
            if (wheel != 0 && inGraph) {
                cam.offset = mouse; cam.target = world;
                cam.zoom *= (1.0f + wheel * 0.12f);
                if (cam.zoom < 0.3f) cam.zoom = 0.3f;
                if (cam.zoom > 3.0f) cam.zoom = 3.0f;
            }

            if (IsMouseButtonPressed(MOUSE_BUTTON_LEFT) && !inGraph) {
                if (CheckCollisionPointRec(mouse, bNewNode)) openAddNode();
                else if (CheckCollisionPointRec(mouse, bNewEdge)) openAddEdge();
                else if (CheckCollisionPointRec(mouse, bDelNode)) deleteSelected();
                else if (CheckCollisionPointRec(mouse, bDelEdge)) openDelEdge();
                else if (CheckCollisionPointRec(mouse, bSave))   { OpResult r = svc.save();   msg = r.message; msgCol = r.ok ? OKGREEN : ERRRED; }
                else if (CheckCollisionPointRec(mouse, bReload)) { OpResult r = svc.reload(); msg = r.message; msgCol = r.ok ? OKGREEN : ERRRED; if (r.ok) { rebuild(true); clearAnalysis(); } }
                else if (CheckCollisionPointRec(mouse, bBFS))    runTraversal(true);
                else if (CheckCollisionPointRec(mouse, bDFS))    runTraversal(false);
                else if (CheckCollisionPointRec(mouse, bDups))   { showDups = !showDups; if (showDups) computeDups(); else { dupNodes.clear(); dupGroups.clear(); } }
                else if (CheckCollisionPointRec(mouse, bProbable)) openProbable();
                else if (CheckCollisionPointRec(mouse, bScenario)) advanceScenario();
                else if (CheckCollisionPointRec(mouse, bRank))   showDegree = !showDegree;
            }
            if (IsMouseButtonPressed(MOUSE_BUTTON_LEFT) && mouse.x < 200) {  // legend (graph-left)
                for (size_t i = 0; i < legendTypes.size(); ++i) {
                    Rectangle lb = { 14.0f, (float)(WIN_H - 206 + (int)i * 22), 16, 16 };
                    if (CheckCollisionPointRec(mouse, lb)) {
                        int tt = (int)legendTypes[i];
                        if (activeTypes.count(tt)) activeTypes.erase(tt); else activeTypes.insert(tt);
                    }
                }
            }
            if (IsMouseButtonPressed(MOUSE_BUTTON_RIGHT) && mouse.x < 200) {  // legenda: listar tipo
                for (size_t i = 0; i < legendTypes.size(); ++i) {
                    Rectangle row = { 14.0f, (float)(WIN_H - 208 + (int)i * 22), 180, 20 };
                    if (CheckCollisionPointRec(mouse, row)) {
                        selected = -1;   // mostrar lista no painel (sem detalhe de no)
                        listType = (listType == (int)legendTypes[i]) ? -1 : (int)legendTypes[i];
                    }
                }
            }

            int hover = -1;
            if (inGraph)
                for (size_t i = 0; i < nodes.size(); ++i)
                    if (visible(nodes[i]) && CheckCollisionPointCircle(world, nodes[i].pos, nodes[i].radius + 3))
                        hover = (int)i;
            bool overLegend = (mouse.x < 200 && mouse.y > WIN_H - 210);
            if (IsMouseButtonPressed(MOUSE_BUTTON_LEFT) && inGraph && !overLegend) {
                if (hover >= 0) { selected = hover; dragging = hover; rebuildNeighbours(); recomputePath(); }
                else { pressEmpty = true; pressPos = mouse; }   // possivel clique para desselecionar
            }
            if (IsMouseButtonDown(MOUSE_BUTTON_LEFT)) {
                if (dragging >= 0) { nodes[dragging].pos = world; nodes[dragging].vel = (Vector2){ 0, 0 }; }
                else if (inGraph && !overLegend) { Vector2 d = GetMouseDelta(); cam.target.x -= d.x / cam.zoom; cam.target.y -= d.y / cam.zoom; }
            }
            if (IsMouseButtonReleased(MOUSE_BUTTON_LEFT)) {
                dragging = -1;
                if (pressEmpty) {
                    float dx = mouse.x - pressPos.x, dy = mouse.y - pressPos.y;
                    if (dx * dx + dy * dy < 25.0f) {   // clique (nao arrasto) em zona vazia -> desselecionar
                        selected = pathDst = -1;
                        path.clear(); pathNodes.clear(); pathEdges.clear(); neighbourSet.clear();
                    }
                    pressEmpty = false;
                }
            }
            if (IsMouseButtonPressed(MOUSE_BUTTON_RIGHT) && hover >= 0) { pathDst = hover; recomputePath(); }
        }

        bool focusMode = (selected >= 0);
        auto nodeDim = [&](int i) {
            if (!focusMode) return false;
            return !(i == selected || neighbourSet.count(i) || pathNodes.count(nodes[i].id));
        };
        int hoverDraw = -1;
        if (formMode == 0 && inGraph)
            for (size_t i = 0; i < nodes.size(); ++i)
                if (visible(nodes[i]) && CheckCollisionPointCircle(world, nodes[i].pos, nodes[i].radius + 3))
                    hoverDraw = (int)i;

        // ---------------- draw ----------------
        BeginDrawing();
        ClearBackground(BG);
        BeginMode2D(cam);

        for (const E& e : edges) {
            if (!visible(nodes[e.a]) || !visible(nodes[e.b])) continue;
            bool inPath = pathEdges.count((long long)e.a * 100000 + e.b) > 0;
            bool touchesSel = focusMode && (e.a == selected || e.b == selected);
            Color col = inPath ? GOLD : EDGE_COL;
            float thick = inPath ? 4.0f : 1.6f;
            if (focusMode && !inPath && !touchesSel) col = Fade(EDGE_COL, 0.25f);
            DrawLineEx(nodes[e.a].pos, nodes[e.b].pos, thick, col);
            Vector2 a = nodes[e.a].pos, b = nodes[e.b].pos;
            float dx = b.x - a.x, dy = b.y - a.y, d = sqrtf(dx * dx + dy * dy) + 0.01f;
            float ux = dx / d, uy = dy / d;
            Vector2 tip = { b.x - ux * (nodes[e.b].radius + 2), b.y - uy * (nodes[e.b].radius + 2) };
            Vector2 l = { tip.x - ux * 10 - uy * 5, tip.y - uy * 10 + ux * 5 };
            Vector2 r = { tip.x - ux * 10 + uy * 5, tip.y - uy * 10 - ux * 5 };
            DrawTriangle(tip, l, r, col);
            if (inPath || touchesSel)
                drawLabel(e.rel.c_str(), (a.x + b.x) / 2, (a.y + b.y) / 2 - 7, 13,
                          inPath ? (Color){ 255, 220, 120, 255 } : TXT);
        }
        for (size_t i = 0; i < nodes.size(); ++i) {
            if (!visible(nodes[i])) continue;
            bool dim = nodeDim((int)i);
            Color c = typeColor(nodes[i].type);
            if (dim) c = Fade(c, 0.22f);
            float r = nodes[i].radius + ((int)i == hoverDraw ? 3.0f : 0.0f);
            DrawCircleV(nodes[i].pos, r, c);
            // anel magenta para potenciais duplicados (resolucao de entidades)
            if (showDups && dupNodes.count(nodes[i].id))
                DrawCircleLines((int)nodes[i].pos.x, (int)nodes[i].pos.y, r + 6, (Color){ 255, 80, 200, 255 });
            if ((int)i == selected)      DrawCircleLines((int)nodes[i].pos.x, (int)nodes[i].pos.y, r + 4, WHITE);
            else if ((int)i == pathDst)  DrawCircleLines((int)nodes[i].pos.x, (int)nodes[i].pos.y, r + 4, GOLD);
            else if (pathNodes.count(nodes[i].id)) DrawCircleLines((int)nodes[i].pos.x, (int)nodes[i].pos.y, r + 2, GOLD);
            else if ((int)i == hoverDraw) DrawCircleLines((int)nodes[i].pos.x, (int)nodes[i].pos.y, r + 2, ACCENT);
            // numero de ordem da travessia BFS/DFS
            auto ti = travIndex.find(nodes[i].id);
            if (ti != travIndex.end()) {
                char ord[8]; snprintf(ord, sizeof(ord), "%d", ti->second);
                drawLabel(ord, nodes[i].pos.x, nodes[i].pos.y - r - 16, 13, (Color){ 120, 230, 160, 255 });
            }
            if (!dim) drawLabel(nodes[i].id.c_str(), nodes[i].pos.x, nodes[i].pos.y + r + 3, 13, TXT);
        }
        EndMode2D();

        drawLabel("Arraste no | clique vazio=desselecionar | pan | zoom | clique dir.=caminho | N no | E relacao | Del apaga | G guardar",
                  GRAPH_W / 2, 12, 12, TXT);

        TX("Tipos (clicar p/ filtrar):", 14, WIN_H - 230, 13, LIGHTGRAY);
        for (size_t i = 0; i < legendTypes.size(); ++i) {
            int y = WIN_H - 206 + (int)i * 22;
            bool on = activeTypes.count((int)legendTypes[i]) > 0;
            Rectangle lb = { 14, (float)y, 16, 16 };
            DrawRectangleRec(lb, on ? typeColor(legendTypes[i]) : (Color){ 40, 48, 66, 255 });
            DrawRectangleLinesEx(lb, 1, DARKGRAY);
            TX(entityTypeToString(legendTypes[i]).c_str(), 38, (float)y + 1, 13, on ? WHITE : GRAY);
        }

        // ---- right panel ----
        DrawRectangle((int)GRAPH_W, 0, PANEL_W, WIN_H, PANEL_BG);
        float px = GRAPH_W + 16, py = 16;
        TX("CTI Knowledge Graph", px, py, 22, ACCENT); py += 28;
        char buf[220];
        snprintf(buf, sizeof(buf), "%d nos | %d relacoes | zoom %.0f%%",
                 (int)nodes.size(), (int)edges.size(), cam.zoom * 100);
        TX(buf, px, py, 13, GRAY); py += 22;

        // search box (procurar no por id)
        TX("Procurar no por id (Enter):", rSearch.x, rSearch.y - 16, 12, LIGHTGRAY);
        DrawRectangleRec(rSearch, FIELD_BG);
        DrawRectangleLinesEx(rSearch, 1, searchActive ? ACCENT : DARKGRAY);
        {
            std::string shown = searchText + (searchActive ? "_" : "");
            if (shown.empty()) { TX("(ex.: apt29)", rSearch.x + 8, rSearch.y + 7, 13, GRAY); }
            else TX(shown.c_str(), rSearch.x + 8, rSearch.y + 7, 13, WHITE);
        }

        button(bNewNode, "Novo no (N)", mouse);
        button(bNewEdge, "Nova relacao (E)", mouse);
        button(bDelNode, "Apagar no (Del)", mouse, selected >= 0);
        button(bDelEdge, "Apagar relacao", mouse);
        button(bSave,   "Guardar BD (G)", mouse);
        button(bReload, "Recarregar BD", mouse);
        button(bBFS, "Travessia BFS", mouse, selected >= 0);
        button(bDFS, "Travessia DFS", mouse, selected >= 0);
        button(bDups, "Duplicados", mouse, true, showDups);
        button(bProbable, "Mais provavel", mouse);
        {
            char sb[40];
            if (scenStep > 0) snprintf(sb, sizeof(sb), "Cenario: passo %d/4 (proximo)", scenStep);
            else snprintf(sb, sizeof(sb), "Cenario (demo narrativa)");
            button(bScenario, sb, mouse, true, scenStep > 0);
        }
        button(bRank, showDegree ? "Ranking: Grau" : "Ranking: PageRank", mouse, true, true);

        if (!msg.empty())
            drawLabel(msg.c_str(), GRAPH_W + PANEL_W / 2.0f, bRank.y + bh + 8, 12, msgCol);

        // available text width and vertical limit (keep clear of bottom ranking)
        const float panelTextW = PANEL_W - 32;
        const float detailLimit = WIN_H - 168;
        // shorten a string to fit `maxW` pixels at size `fs`, adding an ellipsis
        auto fit = [&](std::string s, float maxW, float fs) {
            if (TW(s.c_str(), fs) <= maxW) return s;
            while (s.size() > 1 && TW((s + "...").c_str(), fs) > maxW) s.pop_back();
            return s + "...";
        };
        auto line = [&](const std::string& s, float fs, Color c) {
            if (py > detailLimit) return false;          // clip: no overlap with ranking
            TX(fit(s, panelTextW, fs).c_str(), px, py, fs, c);
            py += fs + 4;
            return true;
        };

        py = bRank.y + bh + 32;

        // narrativa do cenário guiado (Nível 5)
        if (scenStep > 0) {
            Color sc = (Color){ 120, 230, 160, 255 };
            if (scenStep == 1) {
                line("PASSO 1 - Indicador suspeito:", 14, sc);
                line("  ioc-hash-sunburst (hash SHA-256)", 12, LIGHTGRAY);
                line("  introduzido / detetado nos logs", 12, GRAY);
            } else if (scenStep == 2) {
                line("PASSO 2 - Malware associado:", 14, sc);
                line("  o indicador aponta para SUNBURST", 12, LIGHTGRAY);
                line("  (ver 'Atores que usam' abaixo)", 12, GRAY);
            } else if (scenStep == 3) {
                line("PASSO 3 - Ator provavel:", 14, sc);
                line("  APT29 / Cozy Bear usa o SUNBURST", 12, LIGHTGRAY);
            } else {
                line("PASSO 4 - Caminho que justifica:", 14, sc);
                line("  ioc-hash-sunburst -> sunburst -> apt29", 12, LIGHTGRAY);
                line("  (caminho BFS realcado no grafo)", 12, GRAY);
            }
            line("[clique 'Cenario' para avancar]", 11, ACCENT);
            py += 6;
        }

        if (selected >= 0) {
            const NodeVis& n = nodes[selected];
            TX("No selecionado:", px, py, 15, ACCENT); py += 20;
            line(n.label, 15, WHITE);
            line(std::string("tipo: ") + entityTypeToString(n.type), 13, LIGHTGRAY);
            snprintf(buf, sizeof(buf), "PageRank: %.4f   grau in=%d out=%d", n.pr, n.indeg, n.outdeg);
            line(buf, 13, LIGHTGRAY); py += 4;

            int shown = 0, maxList = 6;
            line("Saida ->", 13, ACCENT);
            auto outE = g.getOutEdges(n.id);
            for (const Edge* e : outE) {
                if (shown++ >= maxList) { line("  ...", 12, GRAY); break; }
                const Node* tg = g.getNode(e->targetId);
                line(std::string("  ") + relationTypeToString(e->relation) + " -> " +
                     (tg ? tg->label : e->targetId), 12, LIGHTGRAY);
            }
            shown = 0;
            line("Entrada <-", 13, ACCENT);
            auto inE = g.getInEdges(n.id);
            for (const Edge* e : inE) {
                if (shown++ >= maxList) { line("  ...", 12, GRAY); break; }
                const Node* sc = g.getNode(e->sourceId);
                line(std::string("  ") + relationTypeToString(e->relation) + " <- " +
                     (sc ? sc->label : e->sourceId), 12, LIGHTGRAY);
            }
            line("(clique dir. noutro no = caminho)", 11, GRAY);

            // consultas analiticas (Nivel 3)
            if (n.type == EntityType::MALWARE) {
                py += 4; line("Atores que usam (analitica):", 13, ACCENT);
                auto act = Algorithms::actorsUsingMalware(g, n.id);
                if (act.empty()) line("  (nenhum)", 12, GRAY);
                for (auto& a : act) line(std::string("  ") + a, 12, LIGHTGRAY);
                line("Indicadores que apontam:", 13, ACCENT);
                auto iocs = Algorithms::indicatorsForThreat(g, n.id);
                if (iocs.empty()) line("  (nenhum)", 12, GRAY);
                for (auto& x : iocs) line(std::string("  ") + x, 12, LIGHTGRAY);
            } else {
                auto iocs = Algorithms::indicatorsForThreat(g, n.id);
                if (!iocs.empty()) {
                    py += 4; line("Indicadores que apontam:", 13, ACCENT);
                    for (auto& x : iocs) line(std::string("  ") + x, 12, LIGHTGRAY);
                }
            }
        } else {
            // estatisticas por tipo (Nivel 4)
            line("Estatisticas por tipo:", 14, ACCENT);
            std::map<std::string, int> byType;
            for (auto& nv : nodes) byType[entityTypeToString(nv.type)]++;
            for (auto& kv : byType)
                line(std::string("  ") + kv.first + ": " + std::to_string(kv.second), 12, LIGHTGRAY);
            // lista por tipo (clique direito na legenda)
            if (listType >= 0) {
                py += 4;
                line(std::string("Nos do tipo ") + entityTypeToString((EntityType)listType) + ":", 13, ACCENT);
                bool validT; auto lst = svc.listNodesByType(entityTypeToString((EntityType)listType), validT);
                for (auto* nn : lst) line(std::string("  ") + nn->id, 12, LIGHTGRAY);
            } else {
                line("(clique dir. na legenda p/ listar tipo)", 11, GRAY);
            }
        }

        // travessia BFS/DFS a partir do no selecionado (Nivel 3)
        if (!travMode.empty()) {
            py += 4;
            line(std::string("Travessia ") + travMode + ":", 14, (Color){ 120, 230, 160, 255 });
            std::string ts;
            for (size_t i = 0; i < travOrder.size(); ++i) ts += (i ? " -> " : "") + travOrder[i];
            line(ts, 12, (Color){ 170, 220, 190, 255 });
        }

        // grupos de duplicados detetados (Nivel 3)
        if (showDups) {
            py += 4;
            line("Duplicados (resolucao de entidades):", 13, (Color){ 255, 150, 220, 255 });
            if (dupGroups.empty()) line("  (nenhum)", 12, GRAY);
            for (auto& grp : dupGroups) {
                std::string s = "  { ";
                for (size_t i = 0; i < grp.size(); ++i) s += grp[i] + (i + 1 < grp.size() ? ", " : "");
                s += " }";
                line(s, 12, (Color){ 245, 190, 230, 255 });
            }
        }

        // resultado "entidade mais provavel" (Nivel 3 / inferencia)
        if (probTypeShown >= 0 && !probCands.empty()) {
            py += 4;
            line(std::string("Mais provavel ") + entityTypeToString((EntityType)probTypeShown) +
                 " (de " + probSrcId + "):", 13, (Color){ 130, 200, 255, 255 });
            line("  score = PageRank / distancia", 11, GRAY);
            for (size_t i = 0; i < probCands.size() && i < 5; ++i) {
                char b2[120];
                snprintf(b2, sizeof(b2), "  %zu. %s  (d=%d, score=%.4f)",
                         i + 1, probCands[i].id.c_str(), probCands[i].distance, probCands[i].score);
                line(b2, 12, i == 0 ? (Color){ 150, 230, 255, 255 } : LIGHTGRAY);
            }
        }

        if (!path.empty()) {
            py += 4;
            line("Caminho BFS (calculado em C++):", 14, GOLD);
            std::string ps;
            for (size_t i = 0; i < path.size(); ++i) ps += (i ? " -> " : "") + path[i];
            line(ps, 12, (Color){ 255, 220, 120, 255 });
        }

        py = WIN_H - 150;
        if (showDegree) {
            TX("Top centralidade por grau:", px, py, 14, ACCENT); py += 18;
            auto dc = Algorithms::degreeCentrality(g);
            for (size_t i = 0; i < dc.size() && i < 6; ++i) {
                snprintf(buf, sizeof(buf), "  %zu. %s  in=%d out=%d tot=%d",
                         i + 1, dc[i].id.c_str(), dc[i].in, dc[i].out, dc[i].total);
                TX(fit(buf, panelTextW, 11).c_str(), px, py, 11, LIGHTGRAY); py += 16;
            }
        } else {
            TX("Top PageRank:", px, py, 14, ACCENT); py += 18;
            auto ranked = Algorithms::rankEntities(g);
            for (size_t i = 0; i < ranked.size() && i < 6; ++i) {
                snprintf(buf, sizeof(buf), "  %zu. %s  %.3f", i + 1, ranked[i].first.c_str(), ranked[i].second);
                TX(fit(buf, panelTextW, 12).c_str(), px, py, 12, LIGHTGRAY); py += 16;
            }
        }

        // ---- modal form ----
        if (formMode != 0) {
            DrawRectangle(0, 0, WIN_W, WIN_H, Fade(BLACK, 0.55f));
            DrawRectangleRounded(box, 0.05f, 8, (Color){ 28, 34, 52, 255 });
            DrawRectangleLinesEx(box, 2, ACCENT);
            const char* ftitle = (formMode == 1) ? "Criar no"
                               : (formMode == 2) ? "Criar relacao"
                               : (formMode == 3) ? "Apagar relacao" : "Entidade mais provavel";
            TX(ftitle, box.x + 20, box.y + 16, 18, ACCENT);

            auto field = [&](Rectangle r, const char* lbl, const std::string& val, bool active) {
                TX(lbl, r.x, r.y - 18, 12, LIGHTGRAY);
                DrawRectangleRec(r, FIELD_BG);
                DrawRectangleLinesEx(r, 1, active ? ACCENT : DARKGRAY);
                std::string shown = val + (active ? "_" : "");
                TX(shown.c_str(), r.x + 8, r.y + 7, 14, WHITE);
            };
            auto selector = [&](Rectangle prev, Rectangle next, const char* lbl, const std::string& val, bool active) {
                TX(lbl, prev.x, prev.y - 18, 12, LIGHTGRAY);
                button(prev, "<", mouse);
                button(next, ">", mouse);
                Rectangle mid = { prev.x + 36, prev.y, next.x - prev.x - 42, 30 };
                DrawRectangleRec(mid, FIELD_BG);
                DrawRectangleLinesEx(mid, 1, active ? ACCENT : DARKGRAY);
                TX(val.c_str(), mid.x + (mid.width - TW(val.c_str(), 14)) / 2, mid.y + 7, 14,
                   (Color){ 255, 220, 120, 255 });
            };

            if (formMode == 1) {
                field(rField0, "id (unico) - escreva:", nId, nField == 0);
                field(rField1, "label (nome) - escreva:", nLabel, nField == 1);
                selector(rSelPrev, rSelNext, "tipo (setas ou clique):", TYPES[nTypeIdx], true);
            } else if (formMode == 2 || formMode == 3) {
                std::string s = idList.empty() ? "(vazio)" : idList[eSrcIdx];
                std::string t = idList.empty() ? "(vazio)" : idList[eTgtIdx];
                selector(eRow0Prev, eRow0Next, "origem:", s, eField == 0);
                selector(eRow1Prev, eRow1Next, "destino:", t, eField == 1);
                selector(eRow2Prev, eRow2Next, "relacao:", RELS[eRelIdx], eField == 2);
            } else {   // formMode == 4
                std::string s = idList.empty() ? "(vazio)" : idList[pSrcIdx];
                selector(eRow0Prev, eRow0Next, "a partir de (origem):", s, pField == 0);
                selector(eRow1Prev, eRow1Next, "tipo mais provavel:", TYPES[pTypeIdx], pField == 1);
            }
            const char* okLbl = (formMode == 3) ? "Apagar" : (formMode == 4) ? "Calcular" : "Criar";
            button(rOK, okLbl, mouse);
            button(rCancel, "Cancelar", mouse);
            TX("TAB muda campo | setas escolhem | ENTER confirma | ESC cancela",
               box.x + 20, box.y + box.height - 70, 11, GRAY);
        }

        EndDrawing();
    }

    if (customFont) UnloadFont(g_font);
    CloseWindow();
}

} // namespace Gui
