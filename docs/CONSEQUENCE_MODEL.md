# Consequence Model

## Status: EXPERIMENTAL

`valkyrie/edr/consequence.py` is deliberately one narrow rule, not a generic
claim that privacy activity is malicious. It fires only for a complete,
mature, interactive browser/document CGO with one Nyx leak destination and a
rare descendant egress artifact.

The finding describes a later DNS boundary only. It cannot retroactively stop
the observed HTTP request, bypass encrypted direct-IP traffic, or establish
browser semantic intent. Incomplete, inferred, evicted, ambiguous, or
immature provenance is a suppression, not a verdict.
