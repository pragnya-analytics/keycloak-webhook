package com.pragnya.keycloak.webhook;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class WebhookClientTest {

    private MockWebServer server;
    private WebhookConfig config;
    private WebhookClient client;

    @BeforeEach
    void setUp() throws IOException {
        server = new MockWebServer();
        server.start();

        String url = server.url("/webhook").toString();
        config = new WebhookConfig(url, "test-secret", 2, 5, true, true);
        client = new WebhookClient(config);
    }

    @AfterEach
    void tearDown() throws IOException {
        server.shutdown();
    }

    @Test
    void successfulDeliveryReturnsTrue() throws Exception {
        server.enqueue(new MockResponse().setResponseCode(200));

        boolean result = client.sendAsync("{\"event\":\"LOGIN\"}").get();

        assertTrue(result);
    }

    @Test
    void hmacSignatureHeaderIsPresent() throws Exception {
        server.enqueue(new MockResponse().setResponseCode(200));

        client.sendAsync("{\"event\":\"LOGIN\"}").get();

        RecordedRequest request = server.takeRequest();
        String signature = request.getHeader("X-Keycloak-Signature");
        assertNotNull(signature, "HMAC signature header must be set");
        assertFalse(signature.isEmpty());
    }

    @Test
    void hmacSignatureIsDeterministic() throws Exception {
        server.enqueue(new MockResponse().setResponseCode(200));
        server.enqueue(new MockResponse().setResponseCode(200));

        String payload = "{\"event\":\"LOGIN\"}";
        client.sendAsync(payload).get();
        client.sendAsync(payload).get();

        String sig1 = server.takeRequest().getHeader("X-Keycloak-Signature");
        String sig2 = server.takeRequest().getHeader("X-Keycloak-Signature");
        assertEquals(sig1, sig2, "Same payload must produce same HMAC");
    }

    @Test
    void serverErrorTriggersRetry() throws Exception {
        // Fail once, then succeed — expect exactly 2 requests sent
        server.enqueue(new MockResponse().setResponseCode(503));
        server.enqueue(new MockResponse().setResponseCode(200));

        // Override config to cap retries at 2 with no backoff delay (use minimal)
        String url = server.url("/webhook").toString();
        WebhookConfig retryConfig = new WebhookConfig(url, "secret", 2, 5, false, false);
        WebhookClient retryClient = new WebhookClient(retryConfig);

        boolean result = retryClient.sendAsync("{\"event\":\"REGISTER\"}").get();

        assertTrue(result);
        assertEquals(2, server.getRequestCount());
    }

    @Test
    void clientErrorDoesNotRetry() throws Exception {
        // 4xx should not retry
        server.enqueue(new MockResponse().setResponseCode(401).setBody("Unauthorized"));

        String url = server.url("/webhook").toString();
        WebhookConfig noRetryConfig = new WebhookConfig(url, "secret", 3, 5, false, false);
        WebhookClient noRetryClient = new WebhookClient(noRetryConfig);

        boolean result = noRetryClient.sendAsync("{\"event\":\"LOGIN\"}").get();

        assertFalse(result);
        // Only 1 request despite maxRetries=3
        assertEquals(1, server.getRequestCount());
    }

    @Test
    void allRetriesExhaustedReturnsFalse() throws Exception {
        server.enqueue(new MockResponse().setResponseCode(500));
        server.enqueue(new MockResponse().setResponseCode(500));

        String url = server.url("/webhook").toString();
        WebhookConfig twoRetryConfig = new WebhookConfig(url, "secret", 2, 5, false, false);
        WebhookClient twoRetryClient = new WebhookClient(twoRetryConfig);

        boolean result = twoRetryClient.sendAsync("{\"event\":\"LOGOUT\"}").get();

        assertFalse(result);
        assertEquals(2, server.getRequestCount());
    }
}
