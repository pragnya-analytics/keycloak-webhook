package com.pragnya.keycloak.webhook;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class WebhookConfigTest {
    
    @Test
    void testValidConfiguration() {
        WebhookConfig config = new WebhookConfig(
            "https://example.com/webhook",
            "secret123"
        );
        
        assertTrue(config.isValid());
        assertEquals("https://example.com/webhook", config.getWebhookUrl());
        assertEquals("secret123", config.getSecret());
        assertEquals(3, config.getMaxRetries());
        assertEquals(10, config.getTimeoutSeconds());
        assertTrue(config.isIncludeUserGroups());
        assertTrue(config.isIncludeUserAttributes());
    }
    
    @Test
    void testInvalidConfiguration() {
        WebhookConfig config1 = new WebhookConfig(null, "secret");
        assertFalse(config1.isValid());
        
        WebhookConfig config2 = new WebhookConfig("", "secret");
        assertFalse(config2.isValid());
        
        WebhookConfig config3 = new WebhookConfig("url", null);
        assertFalse(config3.isValid());
        
        WebhookConfig config4 = new WebhookConfig("url", "");
        assertFalse(config4.isValid());
    }
    
    @Test
    void testCustomConfiguration() {
        WebhookConfig config = new WebhookConfig(
            "https://example.com/webhook",
            "secret123",
            5,
            30,
            false,
            false
        );
        
        assertEquals(5, config.getMaxRetries());
        assertEquals(30, config.getTimeoutSeconds());
        assertFalse(config.isIncludeUserGroups());
        assertFalse(config.isIncludeUserAttributes());
    }
}
