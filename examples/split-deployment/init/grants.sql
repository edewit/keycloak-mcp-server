-- What the MCP instances (user kcmcp_mcp) may do, granted by the owner kcmcp_admin once the admin instance has
-- migrated the schema. Run again after every upgrade: a new table has no grants until it is listed here.
--
-- The rule: the MCP side reads the configuration the tools run under and never changes it. A compromised or
-- misbehaving MCP instance cannot register a system, switch an access check off, replace a secret or a key.

-- systems, realms (with their access and tools blocks), secrets, signing keys: read only
GRANT SELECT ON kc_mcp_system, kc_mcp_realm, kc_mcp_secret, kc_mcp_signing_key TO kcmcp_mcp;

-- the audit trail: append only, the rows stay unreadable for the MCP side (the server writes them with a plain
-- INSERT, no RETURNING). The retention purge runs on the admin instance.
GRANT INSERT ON kc_mcp_audit_event TO kcmcp_mcp;

-- CIBA confirmations: the MCP instance that asks for an approval stores and finishes it
GRANT SELECT, INSERT, UPDATE, DELETE ON kc_mcp_pending_approval TO kcmcp_mcp;

-- not listed, so not granted: kc_mcp_user_session (management UI logins) and Liquibase's own tables
