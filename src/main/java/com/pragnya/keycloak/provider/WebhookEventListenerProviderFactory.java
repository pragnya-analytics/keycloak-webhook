package com.pragnya.keycloak.provider;

import com.pragnya.keycloak.webhook.WebhookClient;
import com.pragnya.keycloak.webhook.WebhookConfig;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * Factory for creating WebhookEventListenerProvider instances
 */
public class WebhookEventListenerProviderFactory implements EventListenerProviderFactory {
    private static final Logger logger = Logger.getLogger(WebhookEventListenerProviderFactory.class);
    
    // Environment variable names
    private static final String ENV_WEBHOOK_URL = "WEBHOOK_URL";
    private static final String ENV_WEBHOOK_SECRET = "WEBHOOK_SECRET";
    private static final String ENV_WEBHOOK_MAX_RETRIES = "WEBHOOK_MAX_RETRIES";
    private static final String ENV_WEBHOOK_TIMEOUT = "WEBHOOK_TIMEOUT_SECONDS";
    private static final String ENV_WEBHOOK_INCLUDE_GROUPS = "WEBHOOK_INCLUDE_GROUPS";
    private static final String ENV_WEBHOOK_INCLUDE_ATTRIBUTES = "WEBHOOK_INCLUDE_ATTRIBUTES";
    
    // Alternative environment variable names (for backward compatibility)
    private static final String ENV_ALT_WEBHOOK_URL = "KEYCLOAK_WEBHOOK_URL";
    private static final String ENV_ALT_WEBHOOK_SECRET = "KEYCLOAK_WEBHOOK_SECRET";
    
    private WebhookConfig config;
    private WebhookClient client;
    
    @Override
    public EventListenerProvider create(KeycloakSession session) {
        if (config == null || !config.isValid()) {
            logger.warn("Webhook listener is not properly configured - skipping");
            return new NoOpEventListenerProvider();
        }
        
        return new WebhookEventListenerProvider(session, client, config);
    }
    
    @Override
    public void init(Config.Scope config) {
        logger.info("Initializing Pragnya Webhook Event Listener...");
        
        // Read configuration from environment variables
        String webhookUrl = getEnv(ENV_WEBHOOK_URL, ENV_ALT_WEBHOOK_URL);
        String webhookSecret = getEnv(ENV_WEBHOOK_SECRET, ENV_ALT_WEBHOOK_SECRET);
        
        if (webhookUrl == null || webhookUrl.isEmpty()) {
            logger.warn("WEBHOOK_URL not configured - webhook listener will be disabled");
            return;
        }
        
        if (webhookSecret == null || webhookSecret.isEmpty()) {
            logger.warn("WEBHOOK_SECRET not configured - webhook listener will be disabled");
            return;
        }
        
        // Optional configuration
        int maxRetries = getEnvInt(ENV_WEBHOOK_MAX_RETRIES, 3);
        int timeoutSeconds = getEnvInt(ENV_WEBHOOK_TIMEOUT, 10);
        boolean includeGroups = getEnvBoolean(ENV_WEBHOOK_INCLUDE_GROUPS, true);
        boolean includeAttributes = getEnvBoolean(ENV_WEBHOOK_INCLUDE_ATTRIBUTES, true);
        
        // Create configuration
        this.config = new WebhookConfig(
            webhookUrl, 
            webhookSecret, 
            maxRetries, 
            timeoutSeconds,
            includeGroups, 
            includeAttributes
        );
        
        // Create webhook client
        this.client = new WebhookClient(this.config);
        
        logger.infof("Webhook Event Listener configured successfully:");
        logger.infof("  URL: %s", maskUrl(webhookUrl));
        logger.infof("  Max Retries: %d", maxRetries);
        logger.infof("  Timeout: %d seconds", timeoutSeconds);
        logger.infof("  Include Groups: %b", includeGroups);
        logger.infof("  Include Attributes: %b", includeAttributes);
    }
    
    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // Nothing to do
    }
    
    @Override
    public void close() {
        // Nothing to clean up
    }
    
    @Override
    public String getId() {
        return "webhook_event_listener";
    }
    
    /**
     * Get environment variable with fallback
     */
    private String getEnv(String primaryKey, String fallbackKey) {
        String value = System.getenv(primaryKey);
        if (value == null || value.isEmpty()) {
            value = System.getenv(fallbackKey);
        }
        return value;
    }
    
    /**
     * Get integer environment variable with default
     */
    private int getEnvInt(String key, int defaultValue) {
        String value = System.getenv(key);
        if (value != null && !value.isEmpty()) {
            try {
                return Integer.parseInt(value);
            } catch (NumberFormatException e) {
                logger.warnf("Invalid integer value for %s: %s, using default: %d", 
                           key, value, defaultValue);
            }
        }
        return defaultValue;
    }
    
    /**
     * Get boolean environment variable with default
     */
    private boolean getEnvBoolean(String key, boolean defaultValue) {
        String value = System.getenv(key);
        if (value != null && !value.isEmpty()) {
            return Boolean.parseBoolean(value);
        }
        return defaultValue;
    }
    
    /**
     * Mask URL for logging (hide query params and path after domain)
     */
    private String maskUrl(String url) {
        try {
            java.net.URI uri = new java.net.URI(url);
            return uri.getScheme() + "://" + uri.getHost() + 
                   (uri.getPort() > 0 ? ":" + uri.getPort() : "") + "/***";
        } catch (Exception e) {
            return "***";
        }
    }
    
    /**
     * No-op provider when webhook is not configured
     */
    private static class NoOpEventListenerProvider implements EventListenerProvider {
        @Override
        public void onEvent(org.keycloak.events.Event event) {
            // Do nothing
        }
        
        @Override
        public void onEvent(org.keycloak.events.admin.AdminEvent event, boolean includeRepresentation) {
            // Do nothing
        }
        
        @Override
        public void close() {
            // Do nothing
        }
    }
}
