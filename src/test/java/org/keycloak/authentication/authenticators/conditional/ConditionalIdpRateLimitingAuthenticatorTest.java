package org.keycloak.authentication.authenticators.conditional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.keycloak.authentication.authenticators.conditional.ConditionalIdpRateLimitingAuthenticatorFactory.CONF_IDP_ALIAS;
import static org.keycloak.authentication.authenticators.conditional.ConditionalIdpRateLimitingAuthenticatorFactory.CONF_IDP_LIMIT;
import static org.keycloak.authentication.authenticators.conditional.ConditionalIdpRateLimitingAuthenticatorFactory.CONF_RESET_INTERVAL_HOURS;

class ConditionalIdpRateLimitingAuthenticatorTest {

    private ConditionalIdpRateLimitingAuthenticator authenticator;
    private ConditionalIdpRateLimitingAuthenticatorConfig config;

    @BeforeEach
    void setup() {
        authenticator = ConditionalIdpRateLimitingAuthenticator.SINGLETON;
    }

    @Test
    void testConfigValidation() {
        final Map<String, String> configMap = new HashMap<>();
        configMap.put(CONF_IDP_LIMIT, "5");
        configMap.put(CONF_IDP_ALIAS, "google");
        configMap.put(CONF_RESET_INTERVAL_HOURS, "24");

        config = new ConditionalIdpRateLimitingAuthenticatorConfig(configMap);
        
        assertTrue(config.getIdpLimit() == 5);
        assertTrue(config.getIdpAlias().equals("google"));
        assertFalse(config.isGlobalLimit());
        assertTrue(config.getResetIntervalHours() == 24);
    }

    @Test
    void testGlobalLimitConfig() {
        final Map<String, String> configMap = new HashMap<>();
        configMap.put(CONF_IDP_LIMIT, "10");
        configMap.put(CONF_IDP_ALIAS, "");
        configMap.put(CONF_RESET_INTERVAL_HOURS, "12");

        config = new ConditionalIdpRateLimitingAuthenticatorConfig(configMap);
        
        assertTrue(config.isGlobalLimit());
        assertTrue(config.getIdpLimit() == 10);
        assertTrue(config.getResetIntervalHours() == 12);
    }

    @Test
    void testInvalidLimitThrowsException() {
        final Map<String, String> configMap = new HashMap<>();
        configMap.put(CONF_IDP_LIMIT, "0");
        configMap.put(CONF_IDP_ALIAS, "test");

        try {
            new ConditionalIdpRateLimitingAuthenticatorConfig(configMap);
            assertTrue(false, "Should throw exception for limit <= 0");
        } catch (IllegalStateException e) {
            assertTrue(e.getMessage().contains("greater than 0"));
        }
    }

    @Test
    void testMissingLimitThrowsException() {
        final Map<String, String> configMap = new HashMap<>();
        // Missing CONF_IDP_LIMIT
        configMap.put(CONF_IDP_ALIAS, "test");

        try {
            new ConditionalIdpRateLimitingAuthenticatorConfig(configMap);
            assertTrue(false, "Should throw exception when limit is missing");
        } catch (IllegalStateException e) {
            assertTrue(e.getMessage().contains("not configured"));
        }
    }

    @Test
    void testConfigSettersAndGetters() {
        config = new ConditionalIdpRateLimitingAuthenticatorConfig();
        
        config.setIdpLimit(7);
        config.setIdpAlias("github");
        config.setResetIntervalHours(6);

        assertTrue(config.getIdpLimit() == 7);
        assertTrue(config.getIdpAlias().equals("github"));
        assertFalse(config.isGlobalLimit());
        assertTrue(config.getResetIntervalHours() == 6);

        // Test setting to empty for global limit
        config.setIdpAlias("");
        assertTrue(config.isGlobalLimit());
    }

    @Test
    void testNullIdpAliasBecomesGlobal() {
        config = new ConditionalIdpRateLimitingAuthenticatorConfig();
        config.setIdpLimit(5);
        config.setIdpAlias(null);
        config.setResetIntervalHours(24);

        assertTrue(config.isGlobalLimit());
        assertTrue(config.getIdpAlias().isEmpty());
        assertTrue(config.getResetIntervalHours() == 24);
    }
}
