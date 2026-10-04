# Architectural Decision Log

## Decision 1: Graph Representation Data Structures
* **Status**: Accepted
* **Context**: Need to choose how IAMGraph node and edge data structures are represented in Engine 3.
* **Decision**: Prefer plain Python data structures (`dataclass` and `pydantic` v2 models) with dictionary/set lookups over heavy external graph libraries (such as NetworkX).
* **Rationale**: Keeps execution lightweight, deterministic, dependency-minimal, and fully under unit test control.

## Decision 2: ID Opaceness
* **Status**: Accepted
* **Context**: Pipe-separated string ID parsing was found to have collisions when IAM paths contain `|`.
* **Decision**: All node IDs, permission statement IDs, and edge IDs are treated as opaque strings without splitting or string parsing. Length-prefixed hashing is used when synthesizing new composite IDs.
