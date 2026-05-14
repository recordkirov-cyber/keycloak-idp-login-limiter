package org.keycloak.authentication.authenticators;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.NewCookie;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.EntityTag;
import jakarta.ws.rs.core.Link;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.events.Details;
import org.keycloak.events.Event;
import org.keycloak.events.EventQuery;
import org.keycloak.events.EventStoreProvider;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import java.net.URI;
import java.util.Collections;
import java.util.Date;
import java.util.Locale;
import java.util.Set;

import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.keycloak.authentication.authenticators.IdpRateLimitingAuthenticatorFactory.*;

@DisplayName("IdpRateLimitingAuthenticator Tests")
class IdpRateLimitingAuthenticatorTest {

    private IdpRateLimitingAuthenticator authenticator;
    private IdpRateLimitingAuthenticatorConfig config;

    @BeforeEach
    void setup() {
        authenticator = new IdpRateLimitingAuthenticator();
    }

    private KeycloakSession createSessionWithEventStore(EventStoreProvider eventStore) {
        return (KeycloakSession) Proxy.newProxyInstance(
                KeycloakSession.class.getClassLoader(),
                new Class[]{KeycloakSession.class},
                (proxy, method, args) -> {
                    if ("getProvider".equals(method.getName()) && args != null && args.length == 1
                            && args[0] == EventStoreProvider.class) {
                        return eventStore;
                    }
                    if ("getProvider".equals(method.getName()) && args != null && args.length == 2
                            && args[0] == EventStoreProvider.class) {
                        return eventStore;
                    }
                    if ("close".equals(method.getName())) {
                        return null;
                    }
                    Class<?> returnType = method.getReturnType();
                    if (returnType.isPrimitive()) {
                        if (returnType == boolean.class) return false;
                        if (returnType == byte.class) return (byte) 0;
                        if (returnType == short.class) return (short) 0;
                        if (returnType == int.class) return 0;
                        if (returnType == long.class) return 0L;
                        if (returnType == float.class) return 0f;
                        if (returnType == double.class) return 0d;
                        if (returnType == char.class) return '\0';
                    }
                    return null;
                });
    }

    private static class DummyResponse extends Response {
        @Override
        public int getStatus() {
            return 200;
        }

        @Override
        public StatusType getStatusInfo() {
            return null;
        }

        @Override
        public Object getEntity() {
            return null;
        }

        @Override
        public <T> T readEntity(Class<T> entityType) {
            return null;
        }

        @Override
        public <T> T readEntity(java.lang.Class<T> entityType, java.lang.annotation.Annotation[] annotations) {
            return null;
        }

        @Override
        public <T> T readEntity(jakarta.ws.rs.core.GenericType<T> entityType) {
            return null;
        }

        @Override
        public <T> T readEntity(jakarta.ws.rs.core.GenericType<T> entityType, java.lang.annotation.Annotation[] annotations) {
            return null;
        }

        @Override
        public boolean hasEntity() {
            return false;
        }

        @Override
        public boolean bufferEntity() {
            return false;
        }

        @Override
        public void close() {
        }

        @Override
        public MediaType getMediaType() {
            return null;
        }

        @Override
        public Locale getLanguage() {
            return null;
        }

        @Override
        public int getLength() {
            return 0;
        }

        @Override
        public Set<String> getAllowedMethods() {
            return Collections.emptySet();
        }

        @Override
        public java.util.Map<String, NewCookie> getCookies() {
            return Collections.emptyMap();
        }

        @Override
        public EntityTag getEntityTag() {
            return null;
        }

        @Override
        public Date getDate() {
            return null;
        }

        @Override
        public Date getLastModified() {
            return null;
        }

        @Override
        public URI getLocation() {
            return null;
        }

        @Override
        public Set<Link> getLinks() {
            return Collections.emptySet();
        }

        @Override
        public boolean hasLink(String relation) {
            return false;
        }

        @Override
        public Link getLink(String relation) {
            return null;
        }

        @Override
        public Link.Builder getLinkBuilder(String relation) {
            return null;
        }

        @Override
        public MultivaluedMap<String, Object> getMetadata() {
            return null;
        }

        @Override
        public MultivaluedMap<String, Object> getHeaders() {
            return null;
        }

        @Override
        public MultivaluedMap<String, String> getStringHeaders() {
            return null;
        }

        @Override
        public String getHeaderString(String name) {
            return null;
        }
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
    @DisplayName("Event-based Rate Limiting Tests")
    class EventBasedRateLimitingTests {

        @Test
        @DisplayName("Should allow authentication when successful IdP login events are below limit")
        void testAllowsWhenLoginEventsBelowLimit() {
            AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
            AuthenticatorConfigModel authConfig = new AuthenticatorConfigModel();
            EventStoreProvider eventStore = mock(EventStoreProvider.class);
            KeycloakSession session = createSessionWithEventStore(eventStore);
            RealmModel realm = mock(RealmModel.class);
            UserModel user = mock(UserModel.class);
            EventQuery query = mock(EventQuery.class);
            Event event = new Event();
            event.setError(null);
            event.setDetails(Map.of(Details.IDENTITY_PROVIDER, "google"));

            authConfig.setConfig(Map.of(
                    CONF_IDP_LIMIT, "2",
                    CONF_IDP_ALIAS, "google",
                    CONF_RESET_INTERVAL_HOURS, "24"
            ));
            when(context.getAuthenticatorConfig()).thenReturn(authConfig);
            when(context.getUser()).thenReturn(user);
            when(user.getId()).thenReturn("user-1");
            when(user.getUsername()).thenReturn("jdoe");
            when(context.getRealm()).thenReturn(realm);
            when(realm.getId()).thenReturn("realm-1");
            when(context.getSession()).thenReturn(session);
            when(eventStore.createQuery()).thenReturn(query);
            when(query.type(EventType.LOGIN)).thenReturn(query);
            when(query.realm(anyString())).thenReturn(query);
            when(query.user(anyString())).thenReturn(query);
            when(query.fromDate(anyLong())).thenReturn(query);
            when(query.toDate(anyLong())).thenReturn(query);
            when(query.orderByDescTime()).thenReturn(query);
            when(query.maxResults(anyInt())).thenReturn(query);
            when(query.getResultStream()).thenReturn(Stream.of(event));

            authenticator.authenticate(context);

            verify(context).success();
            verify(context, never()).failure(any(AuthenticationFlowError.class), any(Response.class));
        }

        @Test
        @DisplayName("Should block authentication when successful IdP login events reach limit")
        void testBlocksWhenLoginEventsReachLimit() {
            AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
            AuthenticatorConfigModel authConfig = new AuthenticatorConfigModel();
            EventStoreProvider eventStore = mock(EventStoreProvider.class);
            KeycloakSession session = createSessionWithEventStore(eventStore);
            RealmModel realm = mock(RealmModel.class);
            UserModel user = mock(UserModel.class);
            EventQuery query = mock(EventQuery.class);
            Event event1 = new Event();
            event1.setError(null);
            event1.setDetails(Map.of(Details.IDENTITY_PROVIDER, "google"));
            Event event2 = new Event();
            event2.setError(null);
            event2.setDetails(Map.of(Details.IDENTITY_PROVIDER, "google"));
            LoginFormsProvider formProvider = mock(LoginFormsProvider.class);
            Response errorResponse = new DummyResponse();

            authConfig.setConfig(Map.of(
                    CONF_IDP_LIMIT, "2",
                    CONF_IDP_ALIAS, "google",
                    CONF_RESET_INTERVAL_HOURS, "24"
            ));
            when(context.getAuthenticatorConfig()).thenReturn(authConfig);
            when(context.getUser()).thenReturn(user);
            when(user.getId()).thenReturn("user-1");
            when(user.getUsername()).thenReturn("jdoe");
            when(context.getRealm()).thenReturn(realm);
            when(realm.getId()).thenReturn("realm-1");
            when(context.getSession()).thenReturn(session);
            when(eventStore.createQuery()).thenReturn(query);
            when(query.type(EventType.LOGIN)).thenReturn(query);
            when(query.realm(anyString())).thenReturn(query);
            when(query.user(anyString())).thenReturn(query);
            when(query.fromDate(anyLong())).thenReturn(query);
            when(query.toDate(anyLong())).thenReturn(query);
            when(query.orderByDescTime()).thenReturn(query);
            when(query.maxResults(anyInt())).thenReturn(query);
            when(query.getResultStream()).thenReturn(Stream.of(event1, event2));
            when(context.form()).thenReturn(formProvider);
            when(formProvider.setError(anyString())).thenReturn(formProvider);
            when(formProvider.createErrorPage(any())).thenReturn(errorResponse);

            authenticator.authenticate(context);

            verify(context).failure(eq(AuthenticationFlowError.INVALID_CREDENTIALS), eq(errorResponse));
            verify(context, never()).success();
        }

        @Test
        @DisplayName("Should count events for any provider when global limit is configured")
        void testGlobalLimitCountsAnyIdp() {
            AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
            AuthenticatorConfigModel authConfig = new AuthenticatorConfigModel();
            EventStoreProvider eventStore = mock(EventStoreProvider.class);
            KeycloakSession session = createSessionWithEventStore(eventStore);
            RealmModel realm = mock(RealmModel.class);
            UserModel user = mock(UserModel.class);
            EventQuery query = mock(EventQuery.class);
            Event event1 = new Event();
            event1.setError(null);
            event1.setDetails(Map.of(Details.IDENTITY_PROVIDER, "google"));
            Event event2 = new Event();
            event2.setError(null);
            event2.setDetails(Map.of(Details.IDENTITY_PROVIDER, "github"));
            LoginFormsProvider formProvider = mock(LoginFormsProvider.class);
            Response errorResponse = new DummyResponse();

            authConfig.setConfig(Map.of(
                    CONF_IDP_LIMIT, "2",
                    CONF_IDP_ALIAS, "",
                    CONF_RESET_INTERVAL_HOURS, "24"
            ));
            AuthenticationSessionModel authSession = mock(AuthenticationSessionModel.class);
            when(authSession.getAuthNote("BROKER_IDENTITY_PROVIDER")).thenReturn("google");

            when(context.getAuthenticatorConfig()).thenReturn(authConfig);
            when(context.getUser()).thenReturn(user);
            when(user.getId()).thenReturn("user-1");
            when(user.getUsername()).thenReturn("jdoe");
            when(context.getRealm()).thenReturn(realm);
            when(realm.getId()).thenReturn("realm-1");
            when(context.getSession()).thenReturn(session);
            when(context.getAuthenticationSession()).thenReturn(authSession);
            when(eventStore.createQuery()).thenReturn(query);
            when(query.type(EventType.LOGIN)).thenReturn(query);
            when(query.realm(anyString())).thenReturn(query);
            when(query.user(anyString())).thenReturn(query);
            when(query.fromDate(anyLong())).thenReturn(query);
            when(query.toDate(anyLong())).thenReturn(query);
            when(query.orderByDescTime()).thenReturn(query);
            when(query.maxResults(anyInt())).thenReturn(query);
            when(query.getResultStream()).thenReturn(Stream.of(event1, event2));
            when(context.form()).thenReturn(formProvider);
            when(formProvider.setError(anyString())).thenReturn(formProvider);
            when(formProvider.createErrorPage(any())).thenReturn(errorResponse);

            authenticator.authenticate(context);

            verify(context).failure(eq(AuthenticationFlowError.INVALID_CREDENTIALS), eq(errorResponse));
            verify(context, never()).success();
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
            assertEquals(4, factory.getConfigProperties().size());
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
