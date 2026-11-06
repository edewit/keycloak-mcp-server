package com.acme.keycloak.mcp;

import java.util.List;

import com.github.thomasdarimont.keycloak.mcp.catalog.PromptSpec;
import com.github.thomasdarimont.keycloak.mcp.prompts.PromptProvider;
import com.github.thomasdarimont.keycloak.mcp.spi.ExtensionContext;
import com.google.auto.service.AutoService;

/**
 * Extension point {@link PromptProvider}: a recipe with the tools it needs attached, so the
 * model follows it without a {@code search_tools} round trip.
 */
@AutoService(PromptProvider.class)
public class AcmePrompts implements PromptProvider {

    @Override
    public String id() {
        return "acme-prompts";
    }

    @Override
    public List<PromptSpec> prompts(ExtensionContext ctx) {
        return List.of(PromptSpec.builder("acme_offboard_user").title("Offboard a leaver")
            .description("Check, then offboard a user who leaves the company.")
            .required("username", "Who leaves")
            .argument("ticket", "Change ticket for the offboarding", "")
            .tools("keycloak_acme_user_summary", "keycloak_acme_user_offboard")
            .handler(a -> "Offboard " + a.get("username") + ": first show the user summary and confirm it is the right"
                    + " person, then run the offboarding" + (a.get("ticket").isBlank() ? ""
                            : " with ticket " + a.get("ticket")) + ", and report what changed.")
            .build());
    }
}
