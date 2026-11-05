-- One PostgreSQL server, two databases: Keycloak's own and the MCP server's (kc_mcp_* tables). Never one schema.
CREATE USER kcmcp WITH PASSWORD 'kcmcp';
CREATE DATABASE kcmcp OWNER kcmcp;
