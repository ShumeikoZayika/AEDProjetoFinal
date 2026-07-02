#ifndef TYPES_H
#define TYPES_H

#include <string>
#include <set>
#include <map>

// Entity types supported in the knowledge graph
enum class EntityType {
    THREAT_ACTOR,
    MALWARE,
    INDICATOR,
    CAMPAIGN,
    VULNERABILITY,
    IDENTITY,
    ATTACK_PATTERN,
    TOOL,
    UNKNOWN
};

// Relation types between entities
enum class RelationType {
    USES,
    INDICATES,
    TARGETS,
    EXPLOITS,
    ATTRIBUTED_TO,
    PART_OF,
    DROPS,
    DELIVERS,
    UNKNOWN
};

// Convert EntityType enum to string
inline std::string entityTypeToString(EntityType t) {
    switch (t) {
        case EntityType::THREAT_ACTOR:   return "threat-actor";
        case EntityType::MALWARE:        return "malware";
        case EntityType::INDICATOR:      return "indicator";
        case EntityType::CAMPAIGN:       return "campaign";
        case EntityType::VULNERABILITY:  return "vulnerability";
        case EntityType::IDENTITY:       return "identity";
        case EntityType::ATTACK_PATTERN: return "attack-pattern";
        case EntityType::TOOL:           return "tool";
        default:                         return "unknown";
    }
}

// Convert string to EntityType enum
inline EntityType stringToEntityType(const std::string& s) {
    if (s == "threat-actor")   return EntityType::THREAT_ACTOR;
    if (s == "malware")        return EntityType::MALWARE;
    if (s == "indicator")      return EntityType::INDICATOR;
    if (s == "campaign")       return EntityType::CAMPAIGN;
    if (s == "vulnerability")  return EntityType::VULNERABILITY;
    if (s == "identity")       return EntityType::IDENTITY;
    if (s == "attack-pattern") return EntityType::ATTACK_PATTERN;
    if (s == "tool")           return EntityType::TOOL;
    return EntityType::UNKNOWN;
}

// Convert RelationType enum to string
inline std::string relationTypeToString(RelationType r) {
    switch (r) {
        case RelationType::USES:          return "uses";
        case RelationType::INDICATES:     return "indicates";
        case RelationType::TARGETS:       return "targets";
        case RelationType::EXPLOITS:      return "exploits";
        case RelationType::ATTRIBUTED_TO: return "attributed-to";
        case RelationType::PART_OF:       return "part-of";
        case RelationType::DROPS:         return "drops";
        case RelationType::DELIVERS:      return "delivers";
        default:                          return "unknown";
    }
}

// Convert string to RelationType enum
inline RelationType stringToRelationType(const std::string& s) {
    if (s == "uses")          return RelationType::USES;
    if (s == "indicates")     return RelationType::INDICATES;
    if (s == "targets")       return RelationType::TARGETS;
    if (s == "exploits")      return RelationType::EXPLOITS;
    if (s == "attributed-to") return RelationType::ATTRIBUTED_TO;
    if (s == "part-of")       return RelationType::PART_OF;
    if (s == "drops")         return RelationType::DROPS;
    if (s == "delivers")      return RelationType::DELIVERS;
    return RelationType::UNKNOWN;
}

// Relation validation key: (source type, relation type, target type)
struct RelationRule {
    EntityType source;
    RelationType relation;
    EntityType target;
};

// Valid relation rules (the allowed-relations matrix)
inline bool isValidRelation(EntityType src, RelationType rel, EntityType tgt) {
    // Matrix of allowed relations as per the project spec (expanded)
    static const RelationRule rules[] = {
        // threat-actor uses malware
        { EntityType::THREAT_ACTOR,   RelationType::USES,          EntityType::MALWARE        },
        // threat-actor uses tool
        { EntityType::THREAT_ACTOR,   RelationType::USES,          EntityType::TOOL           },
        // threat-actor uses attack-pattern
        { EntityType::THREAT_ACTOR,   RelationType::USES,          EntityType::ATTACK_PATTERN },
        // threat-actor targets identity
        { EntityType::THREAT_ACTOR,   RelationType::TARGETS,       EntityType::IDENTITY       },
        // threat-actor attributed-to campaign
        { EntityType::THREAT_ACTOR,   RelationType::ATTRIBUTED_TO, EntityType::CAMPAIGN       },
        // indicator indicates malware
        { EntityType::INDICATOR,      RelationType::INDICATES,     EntityType::MALWARE        },
        // indicator indicates threat-actor
        { EntityType::INDICATOR,      RelationType::INDICATES,     EntityType::THREAT_ACTOR   },
        // indicator indicates campaign
        { EntityType::INDICATOR,      RelationType::INDICATES,     EntityType::CAMPAIGN       },
        // campaign targets identity
        { EntityType::CAMPAIGN,       RelationType::TARGETS,       EntityType::IDENTITY       },
        // campaign uses malware
        { EntityType::CAMPAIGN,       RelationType::USES,          EntityType::MALWARE        },
        // campaign attributed-to threat-actor
        { EntityType::CAMPAIGN,       RelationType::ATTRIBUTED_TO, EntityType::THREAT_ACTOR   },
        // malware uses attack-pattern
        { EntityType::MALWARE,        RelationType::USES,          EntityType::ATTACK_PATTERN },
        // malware exploits vulnerability
        { EntityType::MALWARE,        RelationType::EXPLOITS,      EntityType::VULNERABILITY  },
        // malware drops malware
        { EntityType::MALWARE,        RelationType::DROPS,         EntityType::MALWARE        },
        // malware delivers malware
        { EntityType::MALWARE,        RelationType::DELIVERS,      EntityType::MALWARE        },
        // tool uses attack-pattern
        { EntityType::TOOL,           RelationType::USES,          EntityType::ATTACK_PATTERN },
        // malware part-of campaign
        { EntityType::MALWARE,        RelationType::PART_OF,       EntityType::CAMPAIGN       },
    };

    for (const auto& rule : rules) {
        if (rule.source == src && rule.relation == rel && rule.target == tgt)
            return true;
    }
    return false;
}

#endif
