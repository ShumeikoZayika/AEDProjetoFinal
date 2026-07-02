#ifndef NODE_H
#define NODE_H

#include <string>
#include <map>
#include "types.h"

struct Node {
    std::string id;         // unique identifier, e.g. "apt29"
    std::string label;      // human-readable name, e.g. "APT29 / Cozy Bear"
    EntityType  type;       // entity type
    std::map<std::string, std::string> properties; // extra key-value metadata

    Node() : type(EntityType::UNKNOWN) {}

    Node(const std::string& id, const std::string& label, EntityType type)
        : id(id), label(label), type(type) {}

    void print() const {
        printf("  Node [%s] \"%s\" (type: %s)\n",
               id.c_str(), label.c_str(), entityTypeToString(type).c_str());
        for (const auto& kv : properties)
            printf("    %s: %s\n", kv.first.c_str(), kv.second.c_str());
    }
};

#endif
