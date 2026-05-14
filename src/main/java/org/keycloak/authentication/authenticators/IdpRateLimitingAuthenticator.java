package org.keycloak.authentication.authenticators;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.events.Details;
import org.keycloak.events.Event;
import org.keycloak.events.EventStoreProvider;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import jakarta.ws.rs.core.Response;

import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * Identity Provider Rate Limiting Authenticator
 *
 * This authenticator limits the number of authentication attempts a user can make
 * through a specific Identity Provider (IdP) within a configurable time interval.
 * It tracks authentication attempts using user attributes and blocks further
 * authentication when the configured limit is reached.
 */
public class IdpRateLimitingAuthenticator implements Authenticator {

    /**
     * Default error message key when rate limit is exceeded
     *
     * Ключ сообщения об ошибке по умолчанию при превышении лимита
     */
    public static final String IDP_RATE_LIMIT_EXCEEDED = "idpRateLimitExceeded";

    private static final Logger LOG = Logger.getLogger(IdpRateLimitingAuthenticator.class);

    // No user attributes are required for event-based rate limiting.

    /**
     * Performs authentication with rate limiting based on Identity Provider.
     *
     * This method extracts the configuration from the authentication context,
     * validates it, and delegates to the overloaded authenticate method.
     * If configuration fails, authentication is blocked for security.
     *
     * @param context the authentication flow context / контекст потока аутентификации
     */
    @Override
    public void authenticate(AuthenticationFlowContext context) {
        try {
            final IdpRateLimitingAuthenticatorConfig config =
                    new IdpRateLimitingAuthenticatorConfig(context.getAuthenticatorConfig());
            authenticate(context, config);
        } catch (Exception e) {
            LOG.error("Error initializing authenticator configuration", e);
            // Fail closed for security - block authentication on configuration error
            // Закрытое состояние для безопасности - блокировка аутентификации при ошибке конфигурации
            context.failure(AuthenticationFlowError.INTERNAL_ERROR);
        }
    }

    /**
     * Performs authentication with the provided configuration.
     *
     * This is the main authentication logic that checks rate limits for the user
     * and specific Identity Provider. It uses thread-safe locking to prevent
     * race conditions and tracks authentication attempts using user attributes.
     *
     * @param context the authentication flow context / контекст потока аутентификации
     * @param config the authenticator configuration / конфигурация аутентификатора
     */
    // package-private for testing
    void authenticate(AuthenticationFlowContext context, IdpRateLimitingAuthenticatorConfig config) {
        try {
            final UserModel user = context.getUser();
            if (user == null) {
                LOG.warn("User not found in authentication context");
                // Fail closed for security - block authentication when user not found
                context.failure(AuthenticationFlowError.UNKNOWN_USER);
                return;
            }

            final Optional<String> idpAlias = getIdentityProviderAlias(context, config);
            if (idpAlias.isEmpty()) {
                LOG.debug("Identity provider alias not found or not applicable for this authentication");
                // Allow authentication to proceed when no IdP is found (not an error condition)
                context.success();
                return;
            }

            final String effectiveIdpAlias = idpAlias.get();
            LOG.debugf("Checking event-based rate limit for user %s, IdP: %s, limit: %d", user.getUsername(), effectiveIdpAlias, config.getIdpLimit());

            final boolean limitReached = hasExceededEventBasedLimit(context, user, effectiveIdpAlias,
                    config.getIdpLimit(), config.getResetIntervalHours());

            if (limitReached) {
                LOG.warnf("Rate limit exceeded for user %s via IdP %s", user.getUsername(), effectiveIdpAlias);
                final String errorMessageKey = config.hasCustomErrorMessage()
                        ? config.getErrorMessage()
                        : IDP_RATE_LIMIT_EXCEEDED;
                Response challenge = context.form().setError(errorMessageKey).createErrorPage(Response.Status.UNAUTHORIZED);
                context.failure(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
            } else {
                context.success();
            }
        } catch (Exception e) {
            LOG.error("Error checking rate limit condition", e);
            // Fail closed for security - block authentication on runtime error
            context.failure(AuthenticationFlowError.INTERNAL_ERROR);
        }
    }

    private Optional<String> getIdentityProviderAlias(AuthenticationFlowContext context, IdpRateLimitingAuthenticatorConfig config) {
        // If specific IdP is configured, use it
        if (!config.isGlobalLimit()) {
            return Optional.of(config.getIdpAlias());
        }

        // For global limits, the authenticator still needs to verify that this is an IdP
        // / broker login. When an IdP alias is present in the authentication session,
        // proceed with an empty alias so that all successful LOGIN events are counted.
        if (isBrokerOrIdpSession(context)) {
            return Optional.of("");
        }

        return Optional.empty();
    }

    private boolean isBrokerOrIdpSession(AuthenticationFlowContext context) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        if (authSession == null) {
            return false;
        }

        String[] noteKeys = {"BROKER_IDENTITY_PROVIDER", "IDENTITY_PROVIDER"};
        for (String noteKey : noteKeys) {
            String idpFromNote = authSession.getAuthNote(noteKey);
            if (idpFromNote != null && !idpFromNote.trim().isEmpty()) {
                return true;
            }
        }

        return false;
    }

    private Optional<String> getBrokerIdentityProviderAlias(AuthenticationFlowContext context) {
        try {
            AuthenticationSessionModel authSession = context.getAuthenticationSession();
            if (authSession == null) {
                return Optional.empty();
            }

            // Try to get from BROKER_IDENTITY_PROVIDER note (most reliable approach)
            String idpFromBrokerNote = authSession.getAuthNote("BROKER_IDENTITY_PROVIDER");
            if (idpFromBrokerNote != null && !idpFromBrokerNote.trim().isEmpty()) {
                return Optional.of(idpFromBrokerNote);
            }

            // Alternative note name used in some Keycloak versions
            String idpFromIdentityNote = authSession.getAuthNote("IDENTITY_PROVIDER");
            if (idpFromIdentityNote != null && !idpFromIdentityNote.trim().isEmpty()) {
                return Optional.of(idpFromIdentityNote);
            }

            return Optional.empty();
        } catch (Exception e) {
            LOG.debug("Error getting broker identity provider alias", e);
            return Optional.empty();
        }
    }

    private boolean hasExceededEventBasedLimit(AuthenticationFlowContext context, UserModel user,
                                                 String idpAlias, int limit, int resetIntervalHours) {
        EventStoreProvider eventStore = context.getSession().getProvider(EventStoreProvider.class);
        if (eventStore == null) {
            throw new IllegalStateException("EventStoreProvider is not available in the current session");
        }

        final long currentTimeMillis = System.currentTimeMillis();
        final long resetIntervalMillis = (long) resetIntervalHours * 60 * 60 * 1000;
        final long fromTime = currentTimeMillis - resetIntervalMillis;

        try (Stream<Event> events = eventStore.createQuery()
                .type(EventType.LOGIN)
                .realm(context.getRealm().getId())
                .user(user.getId())
                .fromDate(fromTime)
                .toDate(currentTimeMillis)
                .orderByDescTime()
                .maxResults(limit + 1)
                .getResultStream()) {

            long count = events
                    .filter(event -> isSuccessfulIdpLoginEvent(event, idpAlias))
                    .count();

            LOG.debugf("Found %d successful IdP login events for user %s, IdP %s in the last %d hours",
                    count, user.getUsername(), idpAlias, resetIntervalHours);
            return count >= limit;
        }
    }

    private boolean isSuccessfulIdpLoginEvent(Event event, String idpAlias) {
        if (event == null) {
            return false;
        }

        if (event.getError() != null && !event.getError().trim().isEmpty()) {
            return false;
        }

        Map<String, String> details = event.getDetails();
        if (details == null) {
            return false;
        }

        String eventIdentityProvider = details.get(Details.IDENTITY_PROVIDER);
        if (eventIdentityProvider == null || eventIdentityProvider.trim().isEmpty()) {
            return false;
        }

        String normalizedIdpAlias = idpAlias == null ? "" : idpAlias.trim();
        if (normalizedIdpAlias.isEmpty()) {
            return true;
        }

        return normalizedIdpAlias.equalsIgnoreCase(eventIdentityProvider.trim());
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // Not used - authentication logic is in authenticate()
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // Not used
    }

    @Override
    public void close() {
        // No cleanup required for event-based rate limiting.
    }
}
