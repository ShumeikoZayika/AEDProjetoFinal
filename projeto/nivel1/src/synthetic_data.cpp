#include "synthetic_data.h"

void loadSyntheticData(Graph& g) {
    // ---- Threat actors ----
    Node apt29("apt29", "APT29 / Cozy Bear", EntityType::THREAT_ACTOR);
    apt29.properties["origin"] = "Russia";
    apt29.properties["alias"]  = "Cozy Bear";
    g.addNode(apt29);

    Node apt28("apt28", "APT28 / Fancy Bear", EntityType::THREAT_ACTOR);
    apt28.properties["origin"] = "Russia";
    apt28.properties["alias"]  = "Fancy Bear";
    g.addNode(apt28);

    Node lazarus("lazarus", "Lazarus Group", EntityType::THREAT_ACTOR);
    lazarus.properties["origin"] = "North Korea";
    g.addNode(lazarus);

    // ---- Malware ----
    Node sunburst("sunburst", "SUNBURST", EntityType::MALWARE);
    sunburst.properties["family"] = "backdoor";
    sunburst.properties["first_seen"] = "2020";
    g.addNode(sunburst);

    Node wannacry("wannacry", "WannaCry", EntityType::MALWARE);
    wannacry.properties["family"] = "ransomware";
    wannacry.properties["first_seen"] = "2017";
    g.addNode(wannacry);

    Node mimikatz("mimikatz", "Mimikatz", EntityType::TOOL);
    mimikatz.properties["type"] = "credential-dumper";
    g.addNode(mimikatz);

    Node teardrop("teardrop", "TEARDROP", EntityType::MALWARE);
    teardrop.properties["family"] = "dropper";
    g.addNode(teardrop);

    // ---- Attack patterns ----
    Node supplyChain("atk-supply-chain", "Supply Chain Compromise (T1195)",
                     EntityType::ATTACK_PATTERN);
    g.addNode(supplyChain);

    Node spearphish("atk-spearphish", "Spear-Phishing Link (T1566.002)",
                    EntityType::ATTACK_PATTERN);
    g.addNode(spearphish);

    Node credDump("atk-cred-dump", "OS Credential Dumping (T1003)",
                  EntityType::ATTACK_PATTERN);
    g.addNode(credDump);

    Node eternalBlue("vuln-ms17-010", "EternalBlue / MS17-010",
                     EntityType::VULNERABILITY);
    eternalBlue.properties["cvss"] = "9.3";
    g.addNode(eternalBlue);

    // ---- Campaigns ----
    Node solarWindsCamp("camp-solarwinds", "SolarWinds Supply Chain Attack (2020)",
                        EntityType::CAMPAIGN);
    solarWindsCamp.properties["year"] = "2020";
    g.addNode(solarWindsCamp);

    Node wannacryAttack("camp-wannacry", "WannaCry Global Ransomware Campaign (2017)",
                        EntityType::CAMPAIGN);
    wannacryAttack.properties["year"] = "2017";
    g.addNode(wannacryAttack);

    // ---- Identity (targets) ----
    Node usGov("id-usgov", "U.S. Government Agencies", EntityType::IDENTITY);
    usGov.properties["sector"] = "government";
    g.addNode(usGov);

    Node nato("id-nato", "NATO Member States", EntityType::IDENTITY);
    nato.properties["sector"] = "government";
    g.addNode(nato);

    Node hospitals("id-hospitals", "Global Hospitals", EntityType::IDENTITY);
    hospitals.properties["sector"] = "healthcare";
    g.addNode(hospitals);

    // ---- Indicators ----
    Node ip1("ioc-ip-185", "185.220.101.45", EntityType::INDICATOR);
    ip1.properties["type"] = "ip-address";
    g.addNode(ip1);

    Node ip2("ioc-ip-91", "91.108.4.0/22", EntityType::INDICATOR);
    ip2.properties["type"] = "ip-range";
    g.addNode(ip2);

    Node hash1("ioc-hash-sunburst",
               "32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
               EntityType::INDICATOR);
    hash1.properties["type"] = "file-hash-sha256";
    g.addNode(hash1);

    Node domain1("ioc-domain-avsvmcloud", "avsvmcloud[.]com", EntityType::INDICATOR);
    domain1.properties["type"] = "domain";
    g.addNode(domain1);

    Node hash2("ioc-hash-wannacry",
               "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
               EntityType::INDICATOR);
    hash2.properties["type"] = "file-hash-sha256";
    g.addNode(hash2);

    // ---- Relations ----

    // APT29 -> SolarWinds campaign
    g.addEdge("apt29", "camp-solarwinds", RelationType::ATTRIBUTED_TO,
              "APT29 attributed to SolarWinds attack by US intelligence");

    // APT29 uses SUNBURST
    g.addEdge("apt29", "sunburst",        RelationType::USES,
              "APT29 deployed SUNBURST as the primary backdoor");

    // APT29 uses Mimikatz
    g.addEdge("apt29", "mimikatz",        RelationType::USES,
              "Used for credential harvesting post-compromise");

    // APT29 targets US Government
    g.addEdge("apt29", "id-usgov",        RelationType::TARGETS);

    // APT29 targets NATO
    g.addEdge("apt29", "id-nato",         RelationType::TARGETS);

    // Campaign targets US Government
    g.addEdge("camp-solarwinds", "id-usgov", RelationType::TARGETS);

    // Campaign uses SUNBURST
    g.addEdge("camp-solarwinds", "sunburst",  RelationType::USES);

    // SUNBURST uses supply-chain attack pattern
    g.addEdge("sunburst", "atk-supply-chain", RelationType::USES,
              "Delivered via trojanised SolarWinds Orion update");

    // SUNBURST drops TEARDROP
    g.addEdge("sunburst", "teardrop",         RelationType::DROPS,
              "SUNBURST used as first-stage loader to drop TEARDROP");

    // TEARDROP is part of SolarWinds campaign
    g.addEdge("teardrop", "camp-solarwinds",  RelationType::PART_OF);

    // Mimikatz uses credential dumping technique
    g.addEdge("mimikatz", "atk-cred-dump",    RelationType::USES);

    // IoCs indicate SUNBURST / APT29
    g.addEdge("ioc-hash-sunburst",   "sunburst",  RelationType::INDICATES,
              "SHA-256 hash of the malicious SolarWinds DLL");
    g.addEdge("ioc-domain-avsvmcloud","sunburst",  RelationType::INDICATES,
              "C2 domain used by SUNBURST");
    g.addEdge("ioc-ip-185",           "apt29",     RelationType::INDICATES,
              "Exit node linked to APT29 infrastructure");

    // APT28 uses spear-phishing
    g.addEdge("apt28", "atk-spearphish", RelationType::USES);
    g.addEdge("apt28", "id-nato",        RelationType::TARGETS);
    g.addEdge("ioc-ip-91", "apt28",      RelationType::INDICATES,
              "IP range associated with APT28 operations");

    // Lazarus -> WannaCry campaign
    g.addEdge("lazarus", "camp-wannacry", RelationType::ATTRIBUTED_TO);
    g.addEdge("lazarus", "wannacry",      RelationType::USES);
    g.addEdge("lazarus", "id-hospitals",  RelationType::TARGETS);

    // WannaCry exploits EternalBlue
    g.addEdge("wannacry", "vuln-ms17-010", RelationType::EXPLOITS,
              "WannaCry spread via the EternalBlue SMB exploit");

    // Campaign targets hospitals
    g.addEdge("camp-wannacry", "id-hospitals", RelationType::TARGETS);
    g.addEdge("camp-wannacry", "wannacry",     RelationType::USES);

    // IoC indicates WannaCry
    g.addEdge("ioc-hash-wannacry", "wannacry", RelationType::INDICATES,
              "Known WannaCry ransomware binary hash");
}
