package org.keycloak.authentication.authenticators.conditional;

import org.keycloak.Config;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Arrays;
import java.util.List;

import static org.keycloak.provider.ProviderConfigProperty.INTEGER_TYPE;
import static org.keycloak.provider.ProviderConfigProperty.STRING_TYPE;

public class IdpRateLimitingAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "idp-rate-limiting";

    static final String CONF_IDP_LIMIT = "idp-limit";
    static final String CONF_IDP_ALIAS = "idp-alias";
    static final String CONF_RESET_INTERVAL_HOURS = "reset-interval-hours";
    static final String CONF_ERROR_MESSAGE = "error-message";

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = new AuthenticationExecutionModel.Requirement[]{
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.ALTERNATIVE,
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
    public String getReferenceCategory() {
        return "IdP Rate Limiting";
    }

    @Override
    public String getDisplayType() {
        return "Identity Provider Rate Limiting";
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
        return "Blocks authentication if the user exceeds the authentication limit for a specific identity provider within the configured time interval. "
                + "The counter is automatically reset after the specified number of hours. "
                + "Use this authenticator to prevent brute-force attacks or limit usage per identity provider. "
                + "Supports both per-IdP limits and global limits across all identity providers.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        final ProviderConfigProperty idpLimit = new ProviderConfigProperty();
        idpLimit.setType(INTEGER_TYPE);
        idpLimit.setName(CONF_IDP_LIMIT);
        idpLimit.setDefaultValue("5");
        idpLimit.setLabel("Authentication limit");
        idpLimit.setHelpText("Maximum number of authentications allowed within the reset interval via the specified identity provider. Must be greater than 0.");
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
        resetIntervalHours.setHelpText("Interval in hours after which the authentication counter is automatically reset. "
                + "Default is 24 hours. For example, setting this to 1 will reset the counter every hour.");
        resetIntervalHours.setRequired(true);

        final ProviderConfigProperty errorMessage = new ProviderConfigProperty();
        errorMessage.setType(STRING_TYPE);
        errorMessage.setName(CONF_ERROR_MESSAGE);
        errorMessage.setLabel("Error message (optional)");
        errorMessage.setHelpText("Custom error message to display when rate limit is exceeded. "
                + "Can be a localization key or plain text. If empty, default error is used. "
                + "Supports parameters: ${username}, ${idpAlias}, ${limit}, ${resetHours}");
        errorMessage.setRequired(false);

        return Arrays.asList(idpLimit, idpAlias, resetIntervalHours, errorMessage);
    }

    @Override
    public org.keycloak.authentication.Authenticator create(org.keycloak.models.KeycloakSession session) {
        return IdpRateLimitingAuthenticator.SINGLETON;
    }
}
