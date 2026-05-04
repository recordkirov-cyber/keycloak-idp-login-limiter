package org.keycloak.authentication.authenticators.conditional;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import jakarta.ws.rs.core.Response;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class IdpRateLimitingAuthenticator implements Authenticator {

    public static final IdpRateLimitingAuthenticator SINGLETON = new IdpRateLimitingAuthenticator();

    private static final Logger LOG = Logger.getLogger(IdpRateLimitingAuthenticator.class);

    private static final String ATTEMPTS_ATTRIBUTE_PREFIX = "idp_attempts_";
    private static final String LAST_RESET_ATTRIBUTE_PREFIX = "idp_last_reset_";

    // Thread-safe lock registry to avoid memory leaks from string interning
    private final ConcurrentHashMap<String, Lock> userLocks = new ConcurrentHashMap<>();

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        try {
            final IdpRateLimitingAuthenticatorConfig config =
                    new IdpRateLimitingAuthenticatorConfig(context.getAuthenticatorConfig());
            authenticate(context, config);
        } catch (Exception e) {
            LOG.error("Error initializing authenticator configuration", e);
            context.success(); // Allow authentication on configuration error
        }
    }

    // package-private for testing
    void authenticate(AuthenticationFlowContext context, IdpRateLimitingAuthenticatorConfig config) {
        try {
            final UserModel user = context.getUser();
            if (user == null) {
                LOG.warn("User not found in authentication context");
                context.success();
                return;
            }

            final Optional<String> idpAlias = getIdentityProviderAlias(context, config);
            if (idpAlias.isEmpty()) {
                LOG.debug("Identity provider alias not found or not applicable for this authentication");
                context.success();
                return;
            }

            final String effectiveIdpAlias = idpAlias.get();
            LOG.debugf("Checking rate limit for IdP: %s, limit: %d", effectiveIdpAlias, config.getIdpLimit());

            // Use proper thread-safe locking mechanism instead of string interning
            final String lockKey = user.getId() + ":" + effectiveIdpAlias;
            final Lock lock = userLocks.computeIfAbsent(lockKey, k -> new ReentrantLock());

            lock.lock();
            try {
                // Check and reset counter if needed
                checkAndResetCounter(user, effectiveIdpAlias, config.getResetIntervalHours());

                // Increment counter and check if limit reached
                final boolean limitReached = incrementAndCheckLimit(user, effectiveIdpAlias, config.getIdpLimit());

                if (limitReached) {
                    LOG.warnf("Rate limit exceeded for user %s via IdP %s", user.getUsername(), effectiveIdpAlias);
                    if (config.hasCustomErrorMessage()) {
                        final String interpolatedMessage = interpolateErrorMessage(config.getErrorMessage(), user.getUsername(), effectiveIdpAlias, config.getIdpLimit(), config.getResetIntervalHours());
                        final Response errorResponse = Response.status(Response.Status.UNAUTHORIZED)
                                .entity(interpolatedMessage)
                                .build();
                        context.failure(AuthenticationFlowError.INVALID_CREDENTIALS, errorResponse);
                    } else {
                        context.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
                    }
                } else {
                    context.success();
                }
            } finally {
                lock.unlock();
            }
        } catch (Exception e) {
            LOG.error("Error checking rate limit condition", e);
            context.success(); // Allow authentication on error
        }
    }

    private Optional<String> getIdentityProviderAlias(AuthenticationFlowContext context, IdpRateLimitingAuthenticatorConfig config) {
        // If specific IdP is configured, use it
        if (!config.isGlobalLimit()) {
            return Optional.of(config.getIdpAlias());
        }

        // Try to get from broker context (when authenticating through broker)
        Optional<String> brokerIdp = getBrokerIdentityProviderAlias(context);
        if (brokerIdp.isPresent()) {
            return brokerIdp;
        }

        // Try to get from authentication session note (for subsequent authentications)
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        if (authSession != null) {
            // Check primary note names
            String[] noteKeys = {"BROKER_IDENTITY_PROVIDER", "IDENTITY_PROVIDER"};
            for (String noteKey : noteKeys) {
                String idpFromNote = authSession.getAuthNote(noteKey);
                if (idpFromNote != null && !idpFromNote.trim().isEmpty()) {
                    return Optional.of(idpFromNote);
                }
            }
        }

        return Optional.empty();
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

    private void checkAndResetCounter(UserModel user, String idpAlias, int resetIntervalHours) {
        final String lastResetKey = generateAttributeKey(idpAlias, LAST_RESET_ATTRIBUTE_PREFIX);
        final String attemptsKey = generateAttributeKey(idpAlias, ATTEMPTS_ATTRIBUTE_PREFIX);

        final String lastResetStr = user.getFirstAttribute(lastResetKey);
        final long currentTimeMillis = System.currentTimeMillis();
        final long resetIntervalMillis = (long) resetIntervalHours * 60 * 60 * 1000;

        boolean shouldReset = true;
        if (lastResetStr != null && !lastResetStr.trim().isEmpty()) {
            try {
                final long lastResetTimestamp = Long.parseLong(lastResetStr);
                shouldReset = (currentTimeMillis - lastResetTimestamp) >= resetIntervalMillis;
            } catch (NumberFormatException e) {
                LOG.warnf("Invalid last reset timestamp for user %s, key %s: %s",
                        user.getUsername(), lastResetKey, lastResetStr);
                shouldReset = true;
            }
        }

        if (shouldReset) {
            user.setSingleAttribute(lastResetKey, String.valueOf(currentTimeMillis));
            user.setSingleAttribute(attemptsKey, "0");
            LOG.debugf("Reset counter for user %s, IdP %s after %d hours", user.getUsername(), idpAlias, resetIntervalHours);
        }
    }

    // Returns true if limit is reached after incrementing
    private boolean incrementAndCheckLimit(UserModel user, String idpAlias, int limit) {
        final String attemptsKey = generateAttributeKey(idpAlias, ATTEMPTS_ATTRIBUTE_PREFIX);
        final int currentAttempts = getCurrentAttemptCount(user, attemptsKey);
        final int newAttempts = currentAttempts + 1;

        user.setSingleAttribute(attemptsKey, String.valueOf(newAttempts));
        LOG.debugf("Incremented attempts for user %s, IdP %s: %d/%d",
                user.getUsername(), idpAlias, newAttempts, limit);

        return newAttempts >= limit;
    }

    /**
     * Gets the current attempt count from user attributes, handling parsing errors gracefully.
     *
     * @param user the user model
     * @param attemptsKey the attribute key for attempts
     * @return the current attempt count (0 if not found or invalid)
     */
    private int getCurrentAttemptCount(UserModel user, String attemptsKey) {
        String currentAttemptsStr = user.getFirstAttribute(attemptsKey);
        if (currentAttemptsStr != null && !currentAttemptsStr.trim().isEmpty()) {
            try {
                return Integer.parseInt(currentAttemptsStr);
            } catch (NumberFormatException e) {
                LOG.warnf("Invalid attempts count for user %s, key %s: %s",
                        user.getUsername(), attemptsKey, currentAttemptsStr);
            }
        }
        return 0;
    }

    private String generateAttributeKey(String idpAlias, String prefix) {
        if (idpAlias == null || idpAlias.trim().isEmpty()) {
            return prefix + "global";
        }
        // Sanitize IdP alias for use as attribute key
        return prefix + idpAlias.toLowerCase().replaceAll("[^a-z0-9-_]", "_");
    }

    /**
     * Interpolates placeholders in the error message with actual values.
     *
     * @param message the error message template
     * @param username the username
     * @param idpAlias the IdP alias
     * @param limit the authentication limit
     * @param resetHours the reset interval in hours
     * @return the interpolated message
     */
    private String interpolateErrorMessage(String message, String username, String idpAlias, int limit, int resetHours) {
        return message
                .replace("${username}", username != null ? username : "")
                .replace("${idpAlias}", idpAlias != null ? idpAlias : "")
                .replace("${limit}", String.valueOf(limit))
                .replace("${resetHours}", String.valueOf(resetHours));
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
        // Cleanup locks to prevent memory leaks
        userLocks.clear();
    }
}
