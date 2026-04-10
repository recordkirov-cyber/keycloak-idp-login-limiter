package org.keycloak.authentication.authenticators.conditional;

//import org.jboss.logging.Logger;
import org.keycloak.models.AuthenticatorConfigModel;

import java.util.Map;
//import java.util.Optional;

import static org.keycloak.authentication.authenticators.conditional.ConditionalIdpRateLimitingAuthenticatorFactory.CONF_IDP_ALIAS;
import static org.keycloak.authentication.authenticators.conditional.ConditionalIdpRateLimitingAuthenticatorFactory.CONF_IDP_LIMIT;

class ConditionalIdpRateLimitingAuthenticatorConfig {

    //private static final Logger LOG = Logger.getLogger(ConditionalIdpRateLimitingAuthenticatorConfig.class);

    private int idpLimit;
    private String idpAlias;

    ConditionalIdpRateLimitingAuthenticatorConfig() {
    }

    ConditionalIdpRateLimitingAuthenticatorConfig(AuthenticatorConfigModel configModel) {
        this(configModel.getConfig());
    }

    ConditionalIdpRateLimitingAuthenticatorConfig(Map<String, String> configMap) {
        this.idpLimit = parseIdpLimit(configMap);
        this.idpAlias = configMap.getOrDefault(CONF_IDP_ALIAS, "");
    }

    private int parseIdpLimit(Map<String, String> configMap) {
        final String idpLimitStr = configMap.get(CONF_IDP_LIMIT);
        if (idpLimitStr == null || idpLimitStr.trim().isEmpty()) {
            throw new IllegalStateException("IDP limit is not configured");
        }

        try {
            final int limit = Integer.parseInt(idpLimitStr.trim());
            if (limit <= 0) {
                throw new IllegalStateException("IDP limit must be greater than 0, but got: " + limit);
            }
            return limit;
        } catch (NumberFormatException e) {
            throw new IllegalStateException("Invalid IDP limit value: " + idpLimitStr, e);
        }
    }

    public int getIdpLimit() {
        return idpLimit;
    }

    public void setIdpLimit(int idpLimit) {
        if (idpLimit <= 0) {
            throw new IllegalArgumentException("IDP limit must be greater than 0");
        }
        this.idpLimit = idpLimit;
    }

    public String getIdpAlias() {
        return idpAlias;
    }

    public void setIdpAlias(String idpAlias) {
        this.idpAlias = idpAlias != null ? idpAlias : "";
    }

    public boolean isGlobalLimit() {
        return idpAlias == null || idpAlias.trim().isEmpty();
    }
}
