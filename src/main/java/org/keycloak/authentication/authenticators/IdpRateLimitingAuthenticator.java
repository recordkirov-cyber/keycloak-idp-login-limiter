package org.keycloak.authentication.authenticators;

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

/**
 * Identity Provider Rate Limiting Authenticator
 *
 * Аутентификатор ограничения входов через провайдер идентификации
 *
 * This authenticator limits the number of authentication attempts a user can make
 * through a specific Identity Provider (IdP) within a configurable time interval.
 * It tracks authentication attempts using user attributes and blocks further
 * authentication when the configured limit is reached.
 *
 * Этот аутентификатор ограничивает количество попыток аутентификации, которые пользователь
 * может выполнить через определенный провайдер идентификации (IdP) в течение настраиваемого
 * временного интервала. Он отслеживает попытки аутентификации с помощью атрибутов пользователя
 * и блокирует дальнейшую аутентификацию при достижении установленного лимита.
 */
public class IdpRateLimitingAuthenticator implements Authenticator {

    /**
     * Default error message key when rate limit is exceeded
     *
     * Ключ сообщения об ошибке по умолчанию при превышении лимита
     */
    public static final String IDP_RATE_LIMIT_EXCEEDED = "idpRateLimitExceeded";

    private static final Logger LOG = Logger.getLogger(IdpRateLimitingAuthenticator.class);

    private static final String ATTEMPTS_ATTRIBUTE_PREFIX = "idp_attempts_";
    private static final String LAST_RESET_ATTRIBUTE_PREFIX = "idp_last_reset_";

    // Thread-safe lock registry with cleanup mechanism
    private static final ConcurrentHashMap<String, Lock> userLocks = new ConcurrentHashMap<>();

    // Timestamps for lock cleanup
    private static final ConcurrentHashMap<String, Long> lockTimestamps = new ConcurrentHashMap<>();

    // Lock cleanup threshold (1 hour)
    private static final long LOCK_CLEANUP_THRESHOLD = 60 * 60 * 1000L;

    // Last cleanup timestamp
    private static volatile long lastCleanupTime = System.currentTimeMillis();

    // Cleanup interval (10 minutes)
    private static final long CLEANUP_INTERVAL = 10 * 60 * 1000L;

    /**
     * Performs authentication with rate limiting based on Identity Provider.
     *
     * Выполняет аутентификацию с ограничением по провайдеру идентификации.
     *
     * This method extracts the configuration from the authentication context,
     * validates it, and delegates to the overloaded authenticate method.
     * If configuration fails, authentication is blocked for security.
     *
     * Этот метод извлекает конфигурацию из контекста аутентификации,
     * проверяет её и делегирует выполнение перегруженному методу authenticate.
     * При ошибке конфигурации аутентификация блокируется в целях безопасности.
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
     * Выполняет аутентификацию с предоставленной конфигурацией.
     *
     * This is the main authentication logic that checks rate limits for the user
     * and specific Identity Provider. It uses thread-safe locking to prevent
     * race conditions and tracks authentication attempts using user attributes.
     *
     * Это основная логика аутентификации, которая проверяет лимиты для пользователя
     * и определенного провайдера идентификации. Использует потокобезопасную блокировку
     * для предотвращения гонок и отслеживает попытки аутентификации через атрибуты пользователя.
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
                context.failure(AuthenticationFlowError.USER_NOT_FOUND);
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
            LOG.debugf("Checking rate limit for IdP: %s, limit: %d", effectiveIdpAlias, config.getIdpLimit());

            // Use proper thread-safe locking mechanism with cleanup tracking
            final String lockKey = user.getId() + ":" + effectiveIdpAlias;
            final Lock lock = userLocks.computeIfAbsent(lockKey, k -> new ReentrantLock());
            lockTimestamps.put(lockKey, System.currentTimeMillis());

            // Perform periodic cleanup
            final long currentTime = System.currentTimeMillis();
            if (currentTime - lastCleanupTime > CLEANUP_INTERVAL) {
                synchronized (IdpRateLimitingAuthenticator.class) {
                    if (currentTime - lastCleanupTime > CLEANUP_INTERVAL) {
                        cleanupExpiredLocks();
                        lastCleanupTime = currentTime;
                    }
                }
            }

            lock.lock();
            try {
                // Check and reset counter if needed
                checkAndResetCounter(user, effectiveIdpAlias, config.getResetIntervalHours());

                // Increment counter and check if limit reached
                final boolean limitReached = incrementAndCheckLimit(user, effectiveIdpAlias, config.getIdpLimit());

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
            } finally {
                lock.unlock();
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
        // Perform periodic lock cleanup to prevent memory leaks
        cleanupExpiredLocks();
    }

    /**
     * Cleans up expired locks to prevent memory leaks.
     * This method removes locks that haven't been accessed for LOCK_CLEANUP_THRESHOLD milliseconds.
     */
    private static void cleanupExpiredLocks() {
        final long currentTime = System.currentTimeMillis();
        final long threshold = LOCK_CLEANUP_THRESHOLD;

        // Create a list of keys to remove to avoid ConcurrentModificationException
        final java.util.List<String> keysToRemove = new java.util.ArrayList<>();
        for (java.util.Map.Entry<String, Long> entry : lockTimestamps.entrySet()) {
            if (currentTime - entry.getValue() > threshold) {
                keysToRemove.add(entry.getKey());
            }
        }

        // Remove the expired entries
        for (String key : keysToRemove) {
            lockTimestamps.remove(key);
            userLocks.remove(key);
        }

        LOG.debugf("Cleaned up %d expired locks", keysToRemove.size());
    }
}
