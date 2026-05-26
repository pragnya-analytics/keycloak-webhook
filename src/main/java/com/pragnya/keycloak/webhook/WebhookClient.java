package com.pragnya.keycloak.webhook;

import org.jboss.logging.Logger;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.HexFormat;
import java.util.concurrent.CompletableFuture;

/**
 * HTTP client for sending webhooks with HMAC-SHA256 signature
 */
public class WebhookClient {
    private static final Logger logger = Logger.getLogger(WebhookClient.class);
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    
    private final HttpClient client;
    private final WebhookConfig config;
    
    public WebhookClient(WebhookConfig config) {
        this.config = config;
        this.client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(config.getTimeoutSeconds()))
            .build();
    }
    
    /**
     * Send webhook asynchronously with retries
     */
    public CompletableFuture<Boolean> sendAsync(String payload) {
        return CompletableFuture.supplyAsync(() -> {
            int attempt = 0;
            Exception lastException = null;
            
            while (attempt < config.getMaxRetries()) {
                attempt++;
                try {
                    boolean success = send(payload, attempt);
                    if (success) {
                        return true;
                    }
                    // send() returns false for non-retryable failures (e.g., 4xx).
                    // Only exceptions (5xx / network errors) trigger a retry.
                    break;
                } catch (Exception e) {
                    lastException = e;
                    logger.warnf("Webhook attempt %d/%d failed: %s", 
                               attempt, config.getMaxRetries(), e.getMessage());
                    
                    if (attempt < config.getMaxRetries()) {
                        // Exponential backoff: 1s, 2s, 4s...
                        try {
                            Thread.sleep(1000L * (1 << (attempt - 1)));
                        } catch (InterruptedException ie) {
                            Thread.currentThread().interrupt();
                            break;
                        }
                    }
                }
            }
            
            if (lastException != null) {
                logger.errorf("Webhook failed after %d attempts: %s", 
                            config.getMaxRetries(), lastException.getMessage());
            }
            return false;
        });
    }
    
    /**
     * Send webhook synchronously (blocking)
     */
    private boolean send(String payload, int attempt) throws Exception {
        // Generate HMAC-SHA256 signature
        String signature = generateHMAC(payload, config.getSecret());
        
        // Build HTTP request
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(config.getWebhookUrl()))
            .header("Content-Type", "application/json")
            .header("User-Agent", "Keycloak-Webhook-Listener/1.0")
            .header("X-Keycloak-Signature", signature)
            .header("X-Webhook-Attempt", String.valueOf(attempt))
            .POST(HttpRequest.BodyPublishers.ofString(payload, StandardCharsets.UTF_8))
            .timeout(Duration.ofSeconds(config.getTimeoutSeconds()))
            .build();
        
        // Send request
        HttpResponse<String> response = client.send(request, 
                                                    HttpResponse.BodyHandlers.ofString());
        
        int statusCode = response.statusCode();
        
        if (statusCode >= 200 && statusCode < 300) {
            logger.debugf("Webhook delivered successfully (attempt %d): HTTP %d", 
                         attempt, statusCode);
            return true;
        } else if (statusCode >= 400 && statusCode < 500) {
            // Client errors are not retryable
            logger.errorf("Webhook rejected (attempt %d): HTTP %d - %s", 
                         attempt, statusCode, response.body());
            return false;
        } else {
            // Server errors are retryable
            logger.warnf("Webhook server error (attempt %d): HTTP %d - %s", 
                        attempt, statusCode, response.body());
            throw new IOException("Server error: HTTP " + statusCode);
        }
    }
    
    /**
     * Generate HMAC-SHA256 signature for payload
     */
    private String generateHMAC(String payload, String secret) throws Exception {
        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        SecretKeySpec secretKey = new SecretKeySpec(
            secret.getBytes(StandardCharsets.UTF_8), 
            HMAC_ALGORITHM
        );
        mac.init(secretKey);
        
        byte[] hmacBytes = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
        
        // Return as hex string (matches common HMAC verification patterns)
        return HexFormat.of().formatHex(hmacBytes);
    }
    
    /**
     * Alternative: Base64-encoded HMAC (uncomment if needed)
     */
    @SuppressWarnings("unused")
    private String generateHMACBase64(String payload, String secret) throws Exception {
        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        SecretKeySpec secretKey = new SecretKeySpec(
            secret.getBytes(StandardCharsets.UTF_8), 
            HMAC_ALGORITHM
        );
        mac.init(secretKey);
        
        byte[] hmacBytes = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(hmacBytes);
    }
}
