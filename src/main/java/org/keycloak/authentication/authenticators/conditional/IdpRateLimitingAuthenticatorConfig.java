package org.keycloak.authentication.authenticators.conditional;

import org.keycloak.models.AuthenticatorConfigModel;

import java.util.Map;

import static org.keycloak.authentication.authenticators.conditional.IdpRateLimitingAuthenticatorFactory.CONF_IDP_ALIAS;
import static org.keycloak.authentication.authenticators.conditional.IdpRateLimitingAuthenticatorFactory.CONF_IDP_LIMIT;
import static org.keycloak.authentication.authenticators.conditional.IdpRateLimitingAuthenticatorFactory.CONF_RESET_INTERVAL_HOURS;

/**
 * Configuration class for the IdP rate limiting authenticator.
 * Holds configuration parameters for controlling authentication limits per identity provider.
 */
class IdpRateLimitingAuthenticatorConfig {

    private int idpLimit;
    private String idpAlias;
    private int resetIntervalHours;

    /**
     * Default constructor for manual configuration.
     */
    IdpRateLimitingAuthenticatorConfig() {
    }

    /**
     * Constructor that initializes configuration from an AuthenticatorConfigModel.
     *
     * @param configModel the Keycloak authenticator configuration model
     * @throws IllegalArgumentException if configuration is invalid
     */
    IdpRateLimitingAuthenticatorConfig(AuthenticatorConfigModel configModel) {
        if (configModel == null) {
            throw new IllegalArgumentException("AuthenticatorConfigModel cannot be null");
        }
        Map<String, String> configMap = configModel.getConfig();
        if (configMap == null) {
            throw new IllegalArgumentException("Configuration map cannot be null");
        }
        this.idpLimit = parseIdpLimit(configMap);
        this.idpAlias = configMap.getOrDefault(CONF_IDP_ALIAS, "");
        this.resetIntervalHours = parseResetIntervalHours(configMap);
    }

    /**
     * Constructor that initializes configuration from a configuration map.
     *
     * @param configMap the configuration map containing parameter values
     * @throws IllegalArgumentException if configuration is invalid
     */
    IdpRateLimitingAuthenticatorConfig(Map<String, String> configMap) {
        if (configMap == null) {
            throw new IllegalArgumentException("Configuration map cannot be null");
        }
        this.idpLimit = parseIdpLimit(configMap);
        this.idpAlias = configMap.getOrDefault(CONF_IDP_ALIAS, "");
        this.resetIntervalHours = parseResetIntervalHours(configMap);
    }

    /**
     * Parses and validates the IdP limit from configuration.
     *
     * @param configMap the configuration map
     * @return the parsed limit value
     * @throws IllegalArgumentException if the limit is not configured or invalid
     */
    private int parseIdpLimit(Map<String, String> configMap) {
        final String idpLimitStr = configMap.get(CONF_IDP_LIMIT);
        if (idpLimitStr == null || idpLimitStr.trim().isEmpty()) {
            throw new IllegalArgumentException("IDP limit is not configured");
        }

        try {
            final int limit = Integer.parseInt(idpLimitStr.trim());
            if (limit <= 0) {
                throw new IllegalArgumentException("IDP limit must be greater than 0, but got: " + limit);
            }
            return limit;
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid IDP limit value: " + idpLimitStr, e);
        }
    }

    /**
     * Parses and validates the reset interval from configuration.
     *
     * @param configMap the configuration map
     * @return the parsed reset interval in hours
     * @throws IllegalArgumentException if the interval is invalid
     */
    private int parseResetIntervalHours(Map<String, String> configMap) {
        final String resetIntervalStr = configMap.getOrDefault(CONF_RESET_INTERVAL_HOURS, "24");
        try {
            final int hours = Integer.parseInt(resetIntervalStr.trim());
            if (hours <= 0) {
                throw new IllegalArgumentException("Reset interval hours must be greater than 0, but got: " + hours);
            }
            return hours;
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid reset interval hours value: " + resetIntervalStr, e);
        }
    }

    /**
     * Gets the IdP authentication limit.
     *
     * @return the maximum number of authentications allowed
     */
    public int getIdpLimit() {
        return idpLimit;
    }

    /**
     * Sets the IdP authentication limit.
     *
     * @param idpLimit the maximum number of authentications allowed (must be > 0)
     * @throws IllegalArgumentException if idpLimit is not positive
     */
    public void setIdpLimit(int idpLimit) {
        if (idpLimit <= 0) {
            throw new IllegalArgumentException("IDP limit must be greater than 0");
        }
        this.idpLimit = idpLimit;
    }

    /**
     * Gets the IdP alias for which the limit applies.
     *
     * @return the IdP alias, or empty string for global limit
     */
    public String getIdpAlias() {
        return idpAlias;
    }

    /**
     * Sets the IdP alias for which the limit applies.
     *
     * @param idpAlias the IdP alias, or null/empty for global limit
     */
    public void setIdpAlias(String idpAlias) {
        this.idpAlias = idpAlias != null ? idpAlias : "";
    }

    /**
     * Checks if this is a global limit (applies to all IdPs).
     *
     * @return true if no specific IdP is configured, false otherwise
     */
    public boolean isGlobalLimit() {
        return idpAlias == null || idpAlias.trim().isEmpty();
    }

    /**
     * Gets the reset interval in hours.
     *
     * @return the interval after which counters are reset
     */
    public int getResetIntervalHours() {
        return resetIntervalHours;
    }

    /**
     * Sets the reset interval in hours.
     *
     * @param resetIntervalHours the interval after which counters are reset (must be > 0)
     * @throws IllegalArgumentException if resetIntervalHours is not positive
     */
    public void setResetIntervalHours(int resetIntervalHours) {
        if (resetIntervalHours <= 0) {
            throw new IllegalArgumentException("Reset interval hours must be greater than 0");
        }
        this.resetIntervalHours = resetIntervalHours;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        IdpRateLimitingAuthenticatorConfig that = (IdpRateLimitingAuthenticatorConfig) o;

        if (idpLimit != that.idpLimit) return false;
        if (resetIntervalHours != that.resetIntervalHours) return false;
        return idpAlias.equals(that.idpAlias);
    }

    @Override
    public int hashCode() {
        int result = idpLimit;
        result = 31 * result + idpAlias.hashCode();
        result = 31 * result + resetIntervalHours;
        return result;
    }

    @Override
    public String toString() {
        return "IdpRateLimitingAuthenticatorConfig{" +
                "idpLimit=" + idpLimit +
                ", idpAlias='" + idpAlias + '\'' +
                ", resetIntervalHours=" + resetIntervalHours +
                '}';
    }
}
