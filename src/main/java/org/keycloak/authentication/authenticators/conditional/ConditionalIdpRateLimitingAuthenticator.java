package org.keycloak.authentication.authenticators.conditional;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;


//import java.time.LocalDate;
//import java.time.ZoneId;
import java.util.Optional;

public class ConditionalIdpRateLimitingAuthenticator implements ConditionalAuthenticator {

    public static final ConditionalIdpRateLimitingAuthenticator SINGLETON = new ConditionalIdpRateLimitingAuthenticator();

    private static final Logger LOG = Logger.getLogger(ConditionalIdpRateLimitingAuthenticator.class);

    private static final String ATTEMPTS_ATTRIBUTE_PREFIX = "idp_attempts_";
    private static final String LAST_RESET_ATTRIBUTE_PREFIX = "idp_last_reset_";
    private static final String REMAINING_ATTEMPTS_ATTRIBUTE_PREFIX = "idp_remaining_attempts_";

    @Override
    public boolean matchCondition(AuthenticationFlowContext context) {
        final ConditionalIdpRateLimitingAuthenticatorConfig config =
                new ConditionalIdpRateLimitingAuthenticatorConfig(context.getAuthenticatorConfig());
        return matchCondition(context, config);
    }

    // package-private for testing
    boolean matchCondition(AuthenticationFlowContext context, ConditionalIdpRateLimitingAuthenticatorConfig config) {
        try {
            final UserModel user = context.getUser();
            if (user == null) {
                LOG.warn("User not found in authentication context");
                return false;
            }

            final Optional<String> idpAlias = getIdentityProviderAlias(context, config);
            if (idpAlias.isEmpty()) {
                LOG.warn("Identity provider alias not found");
                return false;
            }

            final String effectiveIdpAlias = idpAlias.get();
            LOG.debugf("Checking rate limit for IdP: %s, limit: %d", effectiveIdpAlias, config.getIdpLimit());

            // Check and reset counter if needed
            synchronized (user.getId().intern()) {
                checkAndResetCounter(user, effectiveIdpAlias, config.getResetIntervalHours());

                // Increment counter and check if limit reached
                final boolean limitReached = incrementAndCheckLimit(user, effectiveIdpAlias, config.getIdpLimit());

                // Update remaining attempts attribute
                updateRemainingAttempts(user, effectiveIdpAlias, config.getIdpLimit());

                if (limitReached) {
                    LOG.warnf("Rate limit exceeded for user %s via IdP %s", user.getUsername(), effectiveIdpAlias);
                }

                return limitReached;
            }
        } catch (Exception e) {
            LOG.error("Error checking rate limit condition", e);
            return false;
        }
    }

    private Optional<String> getIdentityProviderAlias(AuthenticationFlowContext context, ConditionalIdpRateLimitingAuthenticatorConfig config) {
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
            String idpFromNote = authSession.getAuthNote("IDENTITY_PROVIDER");
            if (idpFromNote != null && !idpFromNote.trim().isEmpty()) {
                return Optional.of(idpFromNote);
            }

            // Alternative note name used in some Keycloak versions
            idpFromNote = authSession.getAuthNote("BROKER_IDENTITY_PROVIDER");
            if (idpFromNote != null && !idpFromNote.trim().isEmpty()) {
                return Optional.of(idpFromNote);
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

            // Try to get from BROKER_IDENTITY_PROVIDER note (more reliable than parsing)
            String idpFromBrokerNote = authSession.getAuthNote("BROKER_IDENTITY_PROVIDER");
            if (idpFromBrokerNote != null && !idpFromBrokerNote.trim().isEmpty()) {
                return Optional.of(idpFromBrokerNote);
            }

            // Fallback: try to parse BROKERED_CONTEXT_NOTE if needed
            String brokerContextKey = "BROKERED_CONTEXT_NOTE";
            String serializedContext = authSession.getAuthNote(brokerContextKey);

            if (serializedContext != null) {
                // Extract IdP alias from serialized context more robustly
                // Look for "idpAlias":"value" pattern
                int idpAliasIndex = serializedContext.indexOf("\"idpAlias\"");
                if (idpAliasIndex != -1) {
                    int colonIndex = serializedContext.indexOf(":", idpAliasIndex);
                    if (colonIndex != -1) {
                        int startIndex = serializedContext.indexOf("\"", colonIndex) + 1;
                        int endIndex = serializedContext.indexOf("\"", startIndex);
                        if (startIndex > 0 && endIndex > startIndex) {
                            String idpAlias = serializedContext.substring(startIndex, endIndex);
                            if (!idpAlias.isEmpty()) {
                                return Optional.of(idpAlias);
                            }
                        }
                    }
                }
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

        String currentAttemptsStr = user.getFirstAttribute(attemptsKey);
        int currentAttempts = 0;

        if (currentAttemptsStr != null && !currentAttemptsStr.trim().isEmpty()) {
            try {
                currentAttempts = Integer.parseInt(currentAttemptsStr);
            } catch (NumberFormatException e) {
                LOG.warnf("Invalid attempts count for user %s, key %s: %s",
                        user.getUsername(), attemptsKey, currentAttemptsStr);
                currentAttempts = 0;
            }
        }

        currentAttempts++;
        user.setSingleAttribute(attemptsKey, String.valueOf(currentAttempts));
        LOG.debugf("Incremented attempts for user %s, IdP %s: %d/%d",
                user.getUsername(), idpAlias, currentAttempts, limit);

        return currentAttempts >= limit;
    }

    private void updateRemainingAttempts(UserModel user, String idpAlias, int limit) {
        final String attemptsKey = generateAttributeKey(idpAlias, ATTEMPTS_ATTRIBUTE_PREFIX);
        final String remainingKey = generateAttributeKey(idpAlias, REMAINING_ATTEMPTS_ATTRIBUTE_PREFIX);

        String currentAttemptsStr = user.getFirstAttribute(attemptsKey);
        int currentAttempts = 0;

        if (currentAttemptsStr != null && !currentAttemptsStr.trim().isEmpty()) {
            try {
                currentAttempts = Integer.parseInt(currentAttemptsStr);
            } catch (NumberFormatException e) {
                LOG.warnf("Invalid attempts count for user %s, key %s: %s",
                        user.getUsername(), attemptsKey, currentAttemptsStr);
                currentAttempts = 0;
            }
        }

        int remaining = Math.max(0, limit - currentAttempts);
        user.setSingleAttribute(remainingKey, String.valueOf(remaining));
    }

    private String generateAttributeKey(String idpAlias, String prefix) {
        if (idpAlias == null || idpAlias.trim().isEmpty()) {
            return prefix + "global";
        }
        // Sanitize IdP alias for use as attribute key
        return prefix + idpAlias.toLowerCase().replaceAll("[^a-z0-9-_]", "_");
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // Not used - this is a conditional authenticator
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // Not used - this is a conditional authenticator
    }

    @Override
    public void close() {
        // Does nothing
    }
}
