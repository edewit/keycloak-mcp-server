-- One PostgreSQL server, two databases: Keycloak's own and the MCP server's (kc_mcp_* tables).
-- The MCP server's database has two users:
--   kcmcp_admin  owns the database and the schema: runs the Liquibase migrations, writes systems, realms, secrets,
--                keys and UI sessions (the admin instance)
--   kcmcp_mcp    reads what the tools need and writes only the audit trail and pending approvals (the MCP
--                instances); its grants come from grants.sql once the tables exist
CREATE USER kcmcp_admin WITH PASSWORD 'kcmcp-admin';
CREATE USER kcmcp_mcp WITH PASSWORD 'kcmcp-mcp';
CREATE DATABASE kcmcp OWNER kcmcp_admin;

\connect kcmcp
-- nobody but the owner creates objects; the reader may connect and see the schema, nothing more by default
REVOKE ALL ON DATABASE kcmcp FROM PUBLIC;
GRANT CONNECT ON DATABASE kcmcp TO kcmcp_admin, kcmcp_mcp;
ALTER SCHEMA public OWNER TO kcmcp_admin;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO kcmcp_mcp;
