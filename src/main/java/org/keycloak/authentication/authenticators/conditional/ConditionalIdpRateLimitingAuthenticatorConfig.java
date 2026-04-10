package org.keycloak.authentication.authenticators.conditional;

//import org.jboss.logging.Logger;
import org.keycloak.models.AuthenticatorConfigModel;

import java.util.Map;
//import java.util.Optional;

import static org.keycloak.authentication.authenticators.conditional.ConditionalIdpRateLimitingAuthenticatorFactory.CONF_IDP_ALIAS;
import static org.keycloak.authentication.authenticators.conditional.ConditionalIdpRateLimitingAuthenticatorFactory.CONF_IDP_LIMIT;
import static org.keycloak.authentication.authenticators.conditional.ConditionalIdpRateLimitingAuthenticatorFactory.CONF_RESET_INTERVAL_HOURS;

class ConditionalIdpRateLimitingAuthenticatorConfig {

    //private static final Logger LOG = Logger.getLogger(ConditionalIdpRateLimitingAuthenticatorConfig.class);

    private int idpLimit;
    private String idpAlias;
    private int resetIntervalHours;

    ConditionalIdpRateLimitingAuthenticatorConfig() {
    }

    ConditionalIdpRateLimitingAuthenticatorConfig(AuthenticatorConfigModel configModel) {
        this(configModel.getConfig());
    }

    ConditionalIdpRateLimitingAuthenticatorConfig(Map<String, String> configMap) {
        this.idpLimit = parseIdpLimit(configMap);
        this.idpAlias = configMap.getOrDefault(CONF_IDP_ALIAS, "");
        this.resetIntervalHours = parseResetIntervalHours(configMap);
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

    private int parseResetIntervalHours(Map<String, String> configMap) {
        final String resetIntervalStr = configMap.getOrDefault(CONF_RESET_INTERVAL_HOURS, "24");
        try {
            final int hours = Integer.parseInt(resetIntervalStr.trim());
            if (hours <= 0) {
                throw new IllegalStateException("Reset interval hours must be greater than 0, but got: " + hours);
            }
            return hours;
        } catch (NumberFormatException e) {
            throw new IllegalStateException("Invalid reset interval hours value: " + resetIntervalStr, e);
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

    public int getResetIntervalHours() {
        return resetIntervalHours;
    }

    public void setResetIntervalHours(int resetIntervalHours) {
        if (resetIntervalHours <= 0) {
            throw new IllegalArgumentException("Reset interval hours must be greater than 0");
        }
        this.resetIntervalHours = resetIntervalHours;
    }
}
