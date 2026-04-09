package com.example.keycloak.auth;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

public class IdpLoginLimiterConditionFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = IdpLoginLimiterConditionAuthenticator.PROVIDER_ID;

    @Override
    public String getDisplayType() {
        return "IdP Login Limiter Condition";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[]{
                AuthenticationExecutionModel.Requirement.REQUIRED,
                AuthenticationExecutionModel.Requirement.DISABLED
        };
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Limits the number of authentications via a specific Identity Provider by tracking a user attribute. Returns false when limit is reached.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of(
            new ProviderConfigProperty(IdpLoginLimiterConditionAuthenticator.CONFIG_IDP_ALIAS,
                "IdP Alias", "Alias of the Identity Provider to limit (e.g., 'google', 'keycloak-oidc').",
                ProviderConfigProperty.STRING_TYPE, null),
            new ProviderConfigProperty(IdpLoginLimiterConditionAuthenticator.CONFIG_LIMIT,
                "Max Logins", "Maximum allowed logins via the specified IdP.",
                ProviderConfigProperty.STRING_TYPE, "5"),
            new ProviderConfigProperty(IdpLoginLimiterConditionAuthenticator.CONFIG_ATTR_NAME,
                "Attribute Name", "User attribute name to store the login counter.",
                ProviderConfigProperty.STRING_TYPE, "idp-login-count")
        );
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return new IdpLoginLimiterConditionAuthenticator();
    }

    @Override public void init(Config.Scope config) {}
    @Override public void postInit(KeycloakSessionFactory factory) {}
    @Override public void close() {}
    @Override public String getId() { return PROVIDER_ID; }
}