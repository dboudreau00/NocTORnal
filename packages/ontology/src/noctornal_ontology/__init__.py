"""NocTORnal ontology package.

Single source of truth for the graph vocabulary (node types, edge types,
selector types) and the per-selector normalisers. Everything else —
the SQL seed, the TypeScript types — is GENERATED from here
(python -m noctornal_ontology.generate). Do not edit generated files.
"""
from noctornal_ontology.definition import (
    EDGE_TYPES,
    NODE_TYPES,
    SELECTOR_TYPES,
    EdgeType,
    NodeType,
    SelectorType,
)
from noctornal_ontology.normalisers import NORMALISERS, normalise

__version__ = "0.1.0"

__all__ = [
    "EDGE_TYPES",
    "NODE_TYPES",
    "SELECTOR_TYPES",
    "EdgeType",
    "NodeType",
    "SelectorType",
    "NORMALISERS",
    "normalise",
    "__version__",
]
