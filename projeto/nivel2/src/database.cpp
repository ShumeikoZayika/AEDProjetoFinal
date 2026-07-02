#include <cstdio>
#include <cstring>
#include "database.h"

Database::Database() : db_(nullptr) {}

Database::~Database() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

// ---------------------------------------------------------------------------
// Public interface
// ---------------------------------------------------------------------------

bool Database::initDB(const std::string& path) {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }

    int rc = sqlite3_open(path.c_str(), &db_);
    if (rc != SQLITE_OK) {
        printf("[DB ERRO] Não foi possível abrir/criar '%s': %s\n",
               path.c_str(), sqlite3_errmsg(db_));
        sqlite3_close(db_);
        db_ = nullptr;
        return false;
    }

    // Enable WAL mode and foreign-key enforcement
    exec("PRAGMA journal_mode=WAL;");
    exec("PRAGMA foreign_keys=ON;");

    return createSchema();
}

bool Database::saveGraph(const Graph& g) {
    if (!db_) { printf("[DB ERRO] Base de dados não aberta.\n"); return false; }

    // Wrap in a transaction for performance
    if (!exec("BEGIN TRANSACTION;")) return false;

    // saveGraph is a full snapshot of the in-memory graph: clear the tables
    // first so repeated saves never duplicate edges and deletions in memory
    // are reflected in the database. Runs inside the transaction, so a
    // failure rolls everything back.
    bool ok = exec("DELETE FROM edges;")
           && exec("DELETE FROM node_properties;")
           && exec("DELETE FROM nodes;");

    // Persist every node (and its properties)
    for (const Node* n : g.getAllNodes()) {
        if (!saveNode(*n)) { ok = false; break; }
    }

    // Persist every edge
    if (ok) {
        for (const Edge* e : g.getAllEdges()) {
            if (!saveEdge(*e)) { ok = false; break; }
        }
    }

    if (ok) {
        exec("COMMIT;");
    } else {
        exec("ROLLBACK;");
        printf("[DB ERRO] saveGraph falhou; transação revertida.\n");
    }
    return ok;
}

bool Database::loadGraph(Graph& g) {
    if (!db_) { printf("[DB ERRO] Base de dados não aberta.\n"); return false; }

    g.clear();

    // ---- Load nodes ----
    const char* nodeSql =
        "SELECT id, label, type FROM nodes;";
    sqlite3_stmt* stmt = nullptr;

    if (sqlite3_prepare_v2(db_, nodeSql, -1, &stmt, nullptr) != SQLITE_OK) {
        printf("[DB ERRO] Falha ao preparar SELECT nodes: %s\n", sqlite3_errmsg(db_));
        return false;
    }
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Node n = nodeFromStmt(stmt);
        g.addNode(n);
    }
    sqlite3_finalize(stmt);

    // ---- Load node properties ----
    const char* propSql =
        "SELECT node_id, key, value FROM node_properties;";
    if (sqlite3_prepare_v2(db_, propSql, -1, &stmt, nullptr) != SQLITE_OK) {
        printf("[DB ERRO] Falha ao preparar SELECT node_properties: %s\n", sqlite3_errmsg(db_));
        return false;
    }
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        std::string nodeId  = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        std::string key     = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        std::string value   = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        g.setNodeProperty(nodeId, key, value);
    }
    sqlite3_finalize(stmt);

    // ---- Load edges ----
    const char* edgeSql =
        "SELECT source_id, target_id, relation, description FROM edges;";
    if (sqlite3_prepare_v2(db_, edgeSql, -1, &stmt, nullptr) != SQLITE_OK) {
        printf("[DB ERRO] Falha ao preparar SELECT edges: %s\n", sqlite3_errmsg(db_));
        return false;
    }
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Edge e = edgeFromStmt(stmt);
        // addEdge validates the relation; if the DB was written by this app it should always pass
        if (!g.addEdge(e.sourceId, e.targetId, e.relation, e.description)) {
            printf("[DB AVISO] Relação inválida ao carregar da DB: %s --%s--> %s\n",
                   e.sourceId.c_str(),
                   relationTypeToString(e.relation).c_str(),
                   e.targetId.c_str());
        }
    }
    sqlite3_finalize(stmt);

    return true;
}

std::vector<Node> Database::searchNodesByType(EntityType type) {
    std::vector<Node> result;
    if (!db_) return result;

    const char* sql = "SELECT id, label, type FROM nodes WHERE type = ?;";
    sqlite3_stmt* stmt = nullptr;

    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return result;

    std::string typeStr = entityTypeToString(type);
    sqlite3_bind_text(stmt, 1, typeStr.c_str(), -1, SQLITE_STATIC);

    while (sqlite3_step(stmt) == SQLITE_ROW)
        result.push_back(nodeFromStmt(stmt));

    sqlite3_finalize(stmt);
    return result;
}

std::vector<Edge> Database::searchEdgesBySource(const std::string& sourceId) {
    std::vector<Edge> result;
    if (!db_) return result;

    const char* sql =
        "SELECT source_id, target_id, relation, description FROM edges WHERE source_id = ?;";
    sqlite3_stmt* stmt = nullptr;

    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return result;
    sqlite3_bind_text(stmt, 1, sourceId.c_str(), -1, SQLITE_STATIC);

    while (sqlite3_step(stmt) == SQLITE_ROW)
        result.push_back(edgeFromStmt(stmt));

    sqlite3_finalize(stmt);
    return result;
}

std::vector<Edge> Database::searchEdgesByTarget(const std::string& targetId) {
    std::vector<Edge> result;
    if (!db_) return result;

    const char* sql =
        "SELECT source_id, target_id, relation, description FROM edges WHERE target_id = ?;";
    sqlite3_stmt* stmt = nullptr;

    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return result;
    sqlite3_bind_text(stmt, 1, targetId.c_str(), -1, SQLITE_STATIC);

    while (sqlite3_step(stmt) == SQLITE_ROW)
        result.push_back(edgeFromStmt(stmt));

    sqlite3_finalize(stmt);
    return result;
}

std::vector<Edge> Database::searchEdgesByRelation(RelationType relation) {
    std::vector<Edge> result;
    if (!db_) return result;

    const char* sql =
        "SELECT source_id, target_id, relation, description FROM edges WHERE relation = ?;";
    sqlite3_stmt* stmt = nullptr;

    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return result;

    std::string relStr = relationTypeToString(relation);
    sqlite3_bind_text(stmt, 1, relStr.c_str(), -1, SQLITE_STATIC);

    while (sqlite3_step(stmt) == SQLITE_ROW)
        result.push_back(edgeFromStmt(stmt));

    sqlite3_finalize(stmt);
    return result;
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

bool Database::exec(const char* sql) {
    char* errMsg = nullptr;
    int rc = sqlite3_exec(db_, sql, nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        printf("[DB ERRO] SQL: %s\n  -> %s\n", sql, errMsg);
        sqlite3_free(errMsg);
        return false;
    }
    return true;
}

bool Database::createSchema() {
    const char* schema = R"SQL(
        CREATE TABLE IF NOT EXISTS nodes (
            id    TEXT PRIMARY KEY,
            label TEXT NOT NULL,
            type  TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS node_properties (
            node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
            key     TEXT NOT NULL,
            value   TEXT NOT NULL,
            PRIMARY KEY (node_id, key)
        );

        CREATE TABLE IF NOT EXISTS edges (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            source_id   TEXT NOT NULL REFERENCES nodes(id),
            target_id   TEXT NOT NULL REFERENCES nodes(id),
            relation    TEXT NOT NULL,
            description TEXT DEFAULT ''
        );

        CREATE INDEX IF NOT EXISTS idx_edges_source   ON edges(source_id);
        CREATE INDEX IF NOT EXISTS idx_edges_target   ON edges(target_id);
        CREATE INDEX IF NOT EXISTS idx_edges_relation ON edges(relation);
        CREATE INDEX IF NOT EXISTS idx_nodes_type     ON nodes(type);
    )SQL";

    return exec(schema);
}

bool Database::saveNode(const Node& node) {
    // INSERT OR REPLACE so repeated saves are idempotent
    const char* sql =
        "INSERT OR REPLACE INTO nodes(id, label, type) VALUES(?, ?, ?);";
    sqlite3_stmt* stmt = nullptr;

    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        printf("[DB ERRO] Falha ao preparar INSERT node: %s\n", sqlite3_errmsg(db_));
        return false;
    }

    std::string typeStr = entityTypeToString(node.type);
    sqlite3_bind_text(stmt, 1, node.id.c_str(),    -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, node.label.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, typeStr.c_str(),    -1, SQLITE_STATIC);

    bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    if (!ok) { printf("[DB ERRO] INSERT node '%s': %s\n", node.id.c_str(), sqlite3_errmsg(db_)); return false; }

    // Save properties
    const char* propSql =
        "INSERT OR REPLACE INTO node_properties(node_id, key, value) VALUES(?, ?, ?);";
    for (const auto& kv : node.properties) {
        if (sqlite3_prepare_v2(db_, propSql, -1, &stmt, nullptr) != SQLITE_OK) return false;
        sqlite3_bind_text(stmt, 1, node.id.c_str(),     -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, kv.first.c_str(),   -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, kv.second.c_str(),  -1, SQLITE_STATIC);
        ok = (sqlite3_step(stmt) == SQLITE_DONE);
        sqlite3_finalize(stmt);
        if (!ok) return false;
    }
    return true;
}

bool Database::saveEdge(const Edge& edge) {
    const char* sql =
        "INSERT INTO edges(source_id, target_id, relation, description) VALUES(?, ?, ?, ?);";
    sqlite3_stmt* stmt = nullptr;

    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        printf("[DB ERRO] Falha ao preparar INSERT edge: %s\n", sqlite3_errmsg(db_));
        return false;
    }

    std::string relStr = relationTypeToString(edge.relation);
    sqlite3_bind_text(stmt, 1, edge.sourceId.c_str(),   -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, edge.targetId.c_str(),   -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, relStr.c_str(),           -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, edge.description.c_str(),-1, SQLITE_STATIC);

    bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    if (!ok) printf("[DB ERRO] INSERT edge %s->%s: %s\n",
                    edge.sourceId.c_str(), edge.targetId.c_str(), sqlite3_errmsg(db_));
    return ok;
}

Node Database::nodeFromStmt(sqlite3_stmt* stmt) {
    std::string id    = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
    std::string label = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
    std::string type  = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
    return Node(id, label, stringToEntityType(type));
}

Edge Database::edgeFromStmt(sqlite3_stmt* stmt) {
    std::string src  = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
    std::string tgt  = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
    std::string rel  = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
    const unsigned char* raw = sqlite3_column_text(stmt, 3);
    std::string desc = raw ? reinterpret_cast<const char*>(raw) : "";
    return Edge(src, tgt, stringToRelationType(rel), desc);
}
