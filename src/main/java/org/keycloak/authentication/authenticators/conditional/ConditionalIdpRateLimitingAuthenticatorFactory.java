package org.keycloak.authentication.authenticators.conditional;

import org.keycloak.Config;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Arrays;
import java.util.List;

import static org.keycloak.provider.ProviderConfigProperty.INTEGER_TYPE;
import static org.keycloak.provider.ProviderConfigProperty.STRING_TYPE;

public class ConditionalIdpRateLimitingAuthenticatorFactory implements ConditionalAuthenticatorFactory {

    public static final String PROVIDER_ID = "conditional-idp-rate-limiting";

    static final String CONF_IDP_LIMIT = "idp-limit";
    static final String CONF_IDP_ALIAS = "idp-alias";
    static final String CONF_RESET_INTERVAL_HOURS = "reset-interval-hours";

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = new AuthenticationExecutionModel.Requirement[]{
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
    };

    @Override
    public void init(Config.Scope config) {
        // no-op
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // no-op
    }

    @Override
    public void close() {
        // no-op
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Condition - Identity Provider Rate Limiting";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Flow is executed only if the user exceeds the authentication limit for a specific identity provider within the configured time interval. "
                + "The counter is automatically reset after the specified number of hours. "
                + "Use this condition before a Deny Access or error handling authenticator to block users who authenticate too many times through the same provider.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        final ProviderConfigProperty idpLimit = new ProviderConfigProperty();
        idpLimit.setType(INTEGER_TYPE);
        idpLimit.setName(CONF_IDP_LIMIT);
        idpLimit.setDefaultValue("5");
        idpLimit.setLabel("Daily authentication limit");
        idpLimit.setHelpText("Maximum number of authentications allowed per day via the specified identity provider. Must be greater than 0.");
        idpLimit.setRequired(true);

        final ProviderConfigProperty idpAlias = new ProviderConfigProperty();
        idpAlias.setType(STRING_TYPE);
        idpAlias.setName(CONF_IDP_ALIAS);
        idpAlias.setLabel("Identity Provider alias (optional)");
        idpAlias.setHelpText("If specified, only authentications through this specific identity provider are counted. "
                + "If left empty, a global counter is used for all identity providers. "
                + "Examples: 'google', 'github', 'keycloak'");
        idpAlias.setRequired(false);

        final ProviderConfigProperty resetIntervalHours = new ProviderConfigProperty();
        resetIntervalHours.setType(INTEGER_TYPE);
        resetIntervalHours.setName(CONF_RESET_INTERVAL_HOURS);
        resetIntervalHours.setDefaultValue("24");
        resetIntervalHours.setLabel("Reset interval (hours)");
        resetIntervalHours.setHelpText("Interval in hours after which the authentication counter is automatically reset. Default is 24 hours (daily).");
        resetIntervalHours.setRequired(true);

        return Arrays.asList(idpLimit, idpAlias, resetIntervalHours);
    }

    @Override
    public ConditionalAuthenticator getSingleton() {
        return ConditionalIdpRateLimitingAuthenticator.SINGLETON;
    }
}
