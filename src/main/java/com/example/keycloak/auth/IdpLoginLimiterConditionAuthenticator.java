package com.example.keycloak.auth;

import org.jboss.logging.Logger;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

public class IdpLoginLimiterConditionAuthenticator implements Authenticator {

    private static final Logger log = Logger.getLogger(IdpLoginLimiterConditionAuthenticator.class);

    public static final String PROVIDER_ID = "idp-login-limiter-condition";
    static final String CONFIG_IDP_ALIAS = "idp.alias";
    static final String CONFIG_LIMIT = "limit";
    static final String CONFIG_ATTR_NAME = "attr.name";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        try {
            if (context == null) {
                return;
            }

            AuthenticationSessionModel authSession = context.getAuthenticationSession();
            if (authSession == null) {
                log.debug("No authentication session found. Allowing access.");
                context.success();
                return;
            }

            String currentIdp = authSession.getAuthNote("identity_provider");
            if (currentIdp == null) {
                log.debug("Not an IdP authentication. Allowing access.");
                context.success();
                return;
            }

            AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();
            if (configModel == null) {
                log.warn("Authenticator config is missing. Allowing access.");
                context.success();
                return;
            }

            String configuredIdp = configModel.getConfig().get(CONFIG_IDP_ALIAS);
            if (configuredIdp == null || !configuredIdp.equals(currentIdp)) {
                log.debugf("Current IdP '%s' does not match configured '%s'. Allowing access.", currentIdp,
                        configuredIdp);
                context.success();
                return;
            }

            UserModel user = context.getUser();
            if (user == null) {
                log.warn("No authenticated user available. Allowing access.");
                context.success();
                return;
            }

            String attrName = configModel.getConfig().getOrDefault(CONFIG_ATTR_NAME, "idp-login-count");
            String limitStr = configModel.getConfig().get(CONFIG_LIMIT);
            int limit = limitStr != null ? Integer.parseInt(limitStr) : 5;

            String countStr = user.getFirstAttribute(attrName);
            int count = countStr != null ? Integer.parseInt(countStr) : 0;

            if (count >= limit) {
                log.warnf("IdP login limit reached for user '%s' via '%s'. Current: %d, Limit: %d",
                        user.getUsername(), currentIdp, count, limit);
                context.attempted();
                return;
            }

            count++;
            user.setSingleAttribute(attrName, String.valueOf(count));
            log.infof("IdP login count incremented for user '%s' via '%s'. New count: %d",
                    user.getUsername(), currentIdp, count);
            context.success();
        } catch (NumberFormatException e) {
            log.error("Invalid limit configuration format. Allowing access.", e);
            context.success();
        } catch (Exception e) {
            log.error("Error during IdP login limiter evaluation. Allowing access.", e);
            context.success();
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        context.success();
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // No required actions
    }

    @Override
    public void close() {
        // No-op
    }
}
