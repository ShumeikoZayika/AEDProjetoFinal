#ifndef EDGE_H
#define EDGE_H

#include <string>
#include "types.h"

struct Edge {
    std::string sourceId;   // id of the source node
    std::string targetId;   // id of the target node
    RelationType relation;  // type of directed relation
    std::string description; // optional human-readable description

    Edge() : relation(RelationType::UNKNOWN) {}

    Edge(const std::string& src, const std::string& tgt, RelationType rel,
         const std::string& desc = "")
        : sourceId(src), targetId(tgt), relation(rel), description(desc) {}

    void print() const {
        printf("  Edge [%s] --%s--> [%s]",
               sourceId.c_str(), relationTypeToString(relation).c_str(), targetId.c_str());
        if (!description.empty())
            printf("  (\"%s\")", description.c_str());
        printf("\n");
    }
};

#endif
