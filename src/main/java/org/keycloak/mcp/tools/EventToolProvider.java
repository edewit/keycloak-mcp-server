package org.keycloak.mcp.tools;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.keycloak.mcp.catalog.Category;
import org.keycloak.mcp.catalog.ToolCall;
import org.keycloak.mcp.catalog.ToolResult;
import org.keycloak.mcp.catalog.ToolSpec;
import org.keycloak.mcp.keycloak.KeycloakAdmin;
import org.keycloak.mcp.keycloak.Views;
import org.keycloak.mcp.spi.ToolProviderContext;
import org.keycloak.representations.idm.AdminEventRepresentation;
import org.keycloak.representations.idm.EventRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;

/**
 * EVENTS: login events and admin events.
 */
public class EventToolProvider extends AbstractToolProvider {

    static final String DATE = "yyyy-MM-dd";

    @Override
    public String id() {
        return "events";
    }

    @Override
    public String displayName() {
        return "Events";
    }

    @Override
    public String description() {
        return "Login events and admin (audit) events.";
    }

    @Override
    public int order() {
        return 85;
    }

    @Override
    public List<ToolSpec> tools(ToolProviderContext context) {
        return List.of(
                tool("keycloak_events_login")
                        .title("List login events")
                        .description("Recent login events (LOGIN, LOGIN_ERROR, LOGOUT, ...) with user, client and IP.")
                        .category(Category.EVENTS).read()
                        .synonyms("failed logins", "who logged in", "login errors", "audit", "brute force", "last login",
                                "ip address", "security log")
                        .schema(schema()
                                .string("type", "Event type, e.g. LOGIN, LOGIN_ERROR, LOGOUT, CODE_TO_TOKEN, "
                                        + "UPDATE_PASSWORD, REGISTER")
                                .string("user", USER_ID)
                                .string("client", "Filter by clientId")
                                .string("ipAddress", "Filter by IP address")
                                .string("dateFrom", "From date, " + DATE)
                                .string("dateTo", "To date, " + DATE)
                                .pagination())
                        .handler(this::loginEvents)
                        .api(get(R + "/events").query("type", "client", "user", "ipAddress", "dateFrom", "dateTo", "first", "max"))
                        .build(),
                tool("keycloak_events_admin")
                        .title("List admin events")
                        .description("Recent admin console / API changes: who changed which resource.")
                        .category(Category.EVENTS).read()
                        .synonyms("audit log", "who changed", "admin actions", "change history", "deleted by whom")
                        .schema(schema()
                                .enumeration("operationType", "Filter by operation", "CREATE", "UPDATE", "DELETE", "ACTION")
                                .string("resourceType", "e.g. USER, CLIENT, REALM, GROUP, REALM_ROLE, AUTH_FLOW")
                                .string("resourcePath", "Resource path filter, e.g. users/<id>")
                                .string("authUser", "Admin who did it: user id (UUID)")
                                .string("dateFrom", "From date, " + DATE)
                                .string("dateTo", "To date, " + DATE)
                                .pagination())
                        .handler(this::adminEvents)
                        .api(get(R + "/admin-events").queryAs("operationTypes", "operationType").query("authUser", "resourcePath", "dateFrom", "dateTo", "first", "max"))
                        .build());
    }

    ToolResult loginEvents(ToolCall call) {
        String userId = null;
        if (call.has("user")) {
            String u = call.str("user");
            userId = KeycloakAdmin.isUuid(u) ? u : kc.findUser(call.realm(), u).getId();
        }
        List<String> types = call.has("type") ? List.of(call.str("type").toUpperCase()) : null;
        List<EventRepresentation> events = kc.realm(call.realm()).getEvents(types, call.str("client"), userId,
                call.str("dateFrom"), call.str("dateTo"), call.str("ipAddress"), call.first(), call.max());
        List<Map<String, Object>> items = new ArrayList<>();
        for (EventRepresentation e : events) {
            Map<String, Object> v = new LinkedHashMap<>();
            v.put("time", Views.iso(e.getTime()));
            v.put("type", e.getType());
            Views.put(v, "userId", e.getUserId());
            Views.put(v, "clientId", e.getClientId());
            Views.put(v, "ipAddress", e.getIpAddress());
            Views.put(v, "error", e.getError());
            if (e.getDetails() != null && !e.getDetails().isEmpty()) {
                v.put("details", e.getDetails());
            }
            items.add(v);
        }
        Map<String, Object> page = Views.page(items, call.max());
        if (items.isEmpty()) {
            RealmRepresentation r = kc.realm(call.realm()).toRepresentation();
            if (!Boolean.TRUE.equals(r.isEventsEnabled())) {
                page.put("hint", "Login events are not saved in this realm. Enable with keycloak_realm_update "
                        + "eventsEnabled=true.");
            }
        }
        return ToolResult.ok(page);
    }

    ToolResult adminEvents(ToolCall call) {
        List<String> ops = call.has("operationType") ? List.of(call.str("operationType")) : null;
        List<AdminEventRepresentation> events = kc.realm(call.realm()).getAdminEvents(ops, null, null,
                call.str("authUser"), null, call.str("resourcePath"), call.str("dateFrom"), call.str("dateTo"),
                call.first(), call.max());
        String resourceType = call.str("resourceType");
        List<Map<String, Object>> items = new ArrayList<>();
        for (AdminEventRepresentation e : events) {
            if (resourceType != null && !resourceType.equalsIgnoreCase(e.getResourceType())) {
                continue;
            }
            Map<String, Object> v = new LinkedHashMap<>();
            v.put("time", Views.iso(e.getTime()));
            v.put("operation", e.getOperationType());
            Views.put(v, "resourceType", e.getResourceType());
            Views.put(v, "resourcePath", e.getResourcePath());
            if (e.getAuthDetails() != null) {
                Views.put(v, "byUserId", e.getAuthDetails().getUserId());
                Views.put(v, "byClientId", e.getAuthDetails().getClientId());
                Views.put(v, "ipAddress", e.getAuthDetails().getIpAddress());
            }
            Views.put(v, "error", e.getError());
            items.add(v);
        }
        Map<String, Object> page = Views.page(items, call.max());
        if (items.isEmpty()) {
            RealmRepresentation r = kc.realm(call.realm()).toRepresentation();
            if (!Boolean.TRUE.equals(r.isAdminEventsEnabled())) {
                page.put("hint", "Admin events are not saved in this realm. Enable with keycloak_realm_update "
                        + "adminEventsEnabled=true.");
            }
        }
        return ToolResult.ok(page);
    }
}
