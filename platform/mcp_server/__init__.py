"""Stage 5 — MCP (Model Context Protocol) server.

AI agents talk to the platform ONLY through this gateway: typed,
schema-validated operations proxied to the Master's REST API. The server:

* never touches PostgreSQL/Redis directly (the master stays single-writer);
* never spawns processes or shells — there is no such capability at all;
* exposes NO triage operation — validate/refute remains a human decision
  (Pillar B), taken through the authenticated REST endpoint;
* speaks the standard MCP protocol over stdio (JSON-RPC 2.0).
"""