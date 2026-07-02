#ifndef SYNTHETIC_DATA_H
#define SYNTHETIC_DATA_H

#include "graph.h"

// Populates the graph with a synthetic CTI scenario:
//   APT29 (Cozy Bear) campaign targeting a NATO identity,
//   using SUNBURST malware and a supply-chain attack pattern,
//   with several indicators pointing back to the actor.
void loadSyntheticData(Graph& g);

#endif
