package com.pragnya.keycloak.webhook;

/**
 * Configuration for webhook delivery
 */
public class WebhookConfig {
    private final String webhookUrl;
    private final String secret;
    private final int maxRetries;
    private final int timeoutSeconds;
    private final boolean includeUserGroups;
    private final boolean includeUserAttributes;

    public WebhookConfig(String webhookUrl, String secret) {
        this(webhookUrl, secret, 3, 10, true, true);
    }

    public WebhookConfig(String webhookUrl, String secret, int maxRetries, 
                        int timeoutSeconds, boolean includeUserGroups, 
                        boolean includeUserAttributes) {
        this.webhookUrl = webhookUrl;
        this.secret = secret;
        this.maxRetries = maxRetries;
        this.timeoutSeconds = timeoutSeconds;
        this.includeUserGroups = includeUserGroups;
        this.includeUserAttributes = includeUserAttributes;
    }

    public String getWebhookUrl() {
        return webhookUrl;
    }

    public String getSecret() {
        return secret;
    }

    public int getMaxRetries() {
        return maxRetries;
    }

    public int getTimeoutSeconds() {
        return timeoutSeconds;
    }

    public boolean isIncludeUserGroups() {
        return includeUserGroups;
    }

    public boolean isIncludeUserAttributes() {
        return includeUserAttributes;
    }

    public boolean isValid() {
        return webhookUrl != null && !webhookUrl.isEmpty() 
            && secret != null && !secret.isEmpty();
    }
}
