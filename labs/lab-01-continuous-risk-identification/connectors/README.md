# API connector boundary

A connector has one job: collect source records and write the registered raw-file contract. It must not decide whether a record represents risk.

The included Okta connector demonstrates pagination, time bounds, collection metadata, guardrails and atomic output. It directly supplies the Okta evidence used by Lab 01. Other vendors should follow this boundary, but each new source still needs an explicit field mapper and scenario requirement.

Credentials belong in environment variables or an enterprise secret manager. Never place them in a notebook, connector configuration file, fixture or Git commit.
