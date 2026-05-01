package org.keycloak.authentication.authenticators.conditional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.keycloak.authentication.authenticators.conditional.IdpRateLimitingAuthenticatorFactory.*;

@DisplayName("IdpRateLimitingAuthenticator Tests")
class IdpRateLimitingAuthenticatorTest {

    private IdpRateLimitingAuthenticator authenticator;
    private IdpRateLimitingAuthenticatorConfig config;

    @BeforeEach
    void setup() {
        authenticator = IdpRateLimitingAuthenticator.SINGLETON;
    }

    @Nested
    @DisplayName("Configuration Tests")
    class ConfigurationTests {

        @Test
        @DisplayName("Should create config with valid parameters")
        void testConfigValidation() {
            final Map<String, String> configMap = new HashMap<>();
            configMap.put(CONF_IDP_LIMIT, "5");
            configMap.put(CONF_IDP_ALIAS, "google");
            configMap.put(CONF_RESET_INTERVAL_HOURS, "24");

            config = new IdpRateLimitingAuthenticatorConfig(configMap);

            assertEquals(5, config.getIdpLimit());
            assertEquals("google", config.getIdpAlias());
            assertFalse(config.isGlobalLimit());
            assertEquals(24, config.getResetIntervalHours());
        }

        @Test
        @DisplayName("Should create config with global limit when alias is empty")
        void testGlobalLimitConfig() {
            final Map<String, String> configMap = new HashMap<>();
            configMap.put(CONF_IDP_LIMIT, "10");
            configMap.put(CONF_IDP_ALIAS, "");
            configMap.put(CONF_RESET_INTERVAL_HOURS, "12");

            config = new IdpRateLimitingAuthenticatorConfig(configMap);

            assertTrue(config.isGlobalLimit());
            assertEquals(10, config.getIdpLimit());
            assertEquals(12, config.getResetIntervalHours());
        }

        @Test
        @DisplayName("Should throw exception for invalid limit (zero)")
        void testInvalidLimitThrowsException() {
            final Map<String, String> configMap = new HashMap<>();
            configMap.put(CONF_IDP_LIMIT, "0");
            configMap.put(CONF_IDP_ALIAS, "test");

            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
                new IdpRateLimitingAuthenticatorConfig(configMap);
            });

            assertTrue(exception.getMessage().contains("greater than 0"));
        }

        @Test
        @DisplayName("Should throw exception for invalid limit (negative)")
        void testNegativeLimitThrowsException() {
            final Map<String, String> configMap = new HashMap<>();
            configMap.put(CONF_IDP_LIMIT, "-5");
            configMap.put(CONF_IDP_ALIAS, "test");

            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
                new IdpRateLimitingAuthenticatorConfig(configMap);
            });

            assertTrue(exception.getMessage().contains("greater than 0"));
        }

        @Test
        @DisplayName("Should throw exception when limit is missing")
        void testMissingLimitThrowsException() {
            final Map<String, String> configMap = new HashMap<>();
            // Missing CONF_IDP_LIMIT
            configMap.put(CONF_IDP_ALIAS, "test");

            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
                new IdpRateLimitingAuthenticatorConfig(configMap);
            });

            assertTrue(exception.getMessage().contains("not configured"));
        }

        @Test
        @DisplayName("Should throw exception for invalid reset interval")
        void testInvalidResetIntervalThrowsException() {
            final Map<String, String> configMap = new HashMap<>();
            configMap.put(CONF_IDP_LIMIT, "5");
            configMap.put(CONF_IDP_ALIAS, "test");
            configMap.put(CONF_RESET_INTERVAL_HOURS, "0");

            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
                new IdpRateLimitingAuthenticatorConfig(configMap);
            });

            assertTrue(exception.getMessage().contains("Reset interval hours must be greater than 0"));
        }

        @Test
        @DisplayName("Should handle config setters and getters correctly")
        void testConfigSettersAndGetters() {
            config = new IdpRateLimitingAuthenticatorConfig();

            config.setIdpLimit(7);
            config.setIdpAlias("github");
            config.setResetIntervalHours(6);

            assertEquals(7, config.getIdpLimit());
            assertEquals("github", config.getIdpAlias());
            assertFalse(config.isGlobalLimit());
            assertEquals(6, config.getResetIntervalHours());

            // Test setting to empty for global limit
            config.setIdpAlias("");
            assertTrue(config.isGlobalLimit());
        }

        @Test
        @DisplayName("Should treat null IdP alias as global limit")
        void testNullIdpAliasBecomesGlobal() {
            config = new IdpRateLimitingAuthenticatorConfig();
            config.setIdpLimit(5);
            config.setIdpAlias(null);
            config.setResetIntervalHours(24);

            assertTrue(config.isGlobalLimit());
            assertEquals("", config.getIdpAlias());
            assertEquals(24, config.getResetIntervalHours());
        }

        @Test
        @DisplayName("Should validate config equality and hash code")
        void testConfigEqualsAndHashCode() {
            Map<String, String> configMap1 = new HashMap<>();
            configMap1.put(CONF_IDP_LIMIT, "5");
            configMap1.put(CONF_IDP_ALIAS, "google");
            configMap1.put(CONF_RESET_INTERVAL_HOURS, "24");

            Map<String, String> configMap2 = new HashMap<>();
            configMap2.put(CONF_IDP_LIMIT, "5");
            configMap2.put(CONF_IDP_ALIAS, "google");
            configMap2.put(CONF_RESET_INTERVAL_HOURS, "24");

            IdpRateLimitingAuthenticatorConfig config1 = new IdpRateLimitingAuthenticatorConfig(configMap1);
            IdpRateLimitingAuthenticatorConfig config2 = new IdpRateLimitingAuthenticatorConfig(configMap2);

            assertEquals(config1, config2);
            assertEquals(config1.hashCode(), config2.hashCode());
            assertNotEquals(config1, null);
            assertNotEquals(config1, new Object());
        }

        @Test
        @DisplayName("Should provide meaningful toString representation")
        void testConfigToString() {
            Map<String, String> configMap = new HashMap<>();
            configMap.put(CONF_IDP_LIMIT, "5");
            configMap.put(CONF_IDP_ALIAS, "google");
            configMap.put(CONF_RESET_INTERVAL_HOURS, "24");

            config = new IdpRateLimitingAuthenticatorConfig(configMap);
            String toStringResult = config.toString();

            assertTrue(toStringResult.contains("IdpRateLimitingAuthenticatorConfig"));
            assertTrue(toStringResult.contains("idpLimit=5"));
            assertTrue(toStringResult.contains("idpAlias='google'"));
            assertTrue(toStringResult.contains("resetIntervalHours=24"));
        }
    }

    @Nested
    @DisplayName("Authenticator Factory Tests")
    class FactoryTests {

        @Test
        @DisplayName("Should create authenticator instance")
        void testFactoryCreatesAuthenticator() {
            IdpRateLimitingAuthenticatorFactory factory = new IdpRateLimitingAuthenticatorFactory();

            assertEquals("idp-rate-limiting", factory.getId());
            assertEquals("Identity Provider Rate Limiting", factory.getDisplayType());
            assertTrue(factory.isConfigurable());
            assertFalse(factory.isUserSetupAllowed());
            assertNotNull(factory.getConfigProperties());
            assertEquals(3, factory.getConfigProperties().size());
        }

        @Test
        @DisplayName("Should provide correct requirement choices")
        void testRequirementChoices() {
            IdpRateLimitingAuthenticatorFactory factory = new IdpRateLimitingAuthenticatorFactory();
            var requirements = factory.getRequirementChoices();

            assertEquals(3, requirements.length);
            assertTrue(requirements[0] == org.keycloak.models.AuthenticationExecutionModel.Requirement.REQUIRED ||
                       requirements[1] == org.keycloak.models.AuthenticationExecutionModel.Requirement.REQUIRED ||
                       requirements[2] == org.keycloak.models.AuthenticationExecutionModel.Requirement.REQUIRED);
        }
    }
}
