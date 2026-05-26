package com.pragnya.keycloak.provider;

import com.pragnya.keycloak.webhook.WebhookClient;
import com.pragnya.keycloak.webhook.WebhookConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.events.Event;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserProvider;

import java.util.concurrent.CompletableFuture;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class WebhookEventListenerProviderTest {

    private WebhookClient mockClient;
    private KeycloakSession mockSession;
    private WebhookConfig config;
    private WebhookEventListenerProvider provider;

    @BeforeEach
    void setUp() {
        mockClient = mock(WebhookClient.class);
        mockSession = mock(KeycloakSession.class);

        KeycloakContext mockContext = mock(KeycloakContext.class);
        RealmModel mockRealm = mock(RealmModel.class);
        UserProvider mockUserProvider = mock(UserProvider.class);

        when(mockSession.getContext()).thenReturn(mockContext);
        when(mockContext.getRealm()).thenReturn(mockRealm);
        when(mockSession.users()).thenReturn(mockUserProvider);
        when(mockUserProvider.getUserById(mockRealm, "user-1")).thenReturn(null);

        config = new WebhookConfig("https://example.com/webhook", "test-secret");
        provider = new WebhookEventListenerProvider(mockSession, mockClient, config);

        when(mockClient.sendAsync(anyString()))
                .thenReturn(CompletableFuture.completedFuture(true));
    }

    @Test
    void monitoredEventTriggersSend() {
        Event event = new Event();
        event.setType(EventType.LOGIN);
        event.setRealmId("test-realm");
        event.setUserId("user-1");

        provider.onEvent(event);

        verify(mockClient).sendAsync(anyString());
    }

    @Test
    void nonMonitoredEventIsSkipped() {
        Event event = new Event();
        event.setType(EventType.SEND_RESET_PASSWORD);

        provider.onEvent(event);

        verify(mockClient, never()).sendAsync(anyString());
    }

    @Test
    void errorEventIsSkipped() {
        Event event = new Event();
        event.setType(EventType.LOGIN);
        event.setError("invalid_user_credentials");

        provider.onEvent(event);

        verify(mockClient, never()).sendAsync(anyString());
    }

    @Test
    void userAdminEventTriggersSend() {
        AdminEvent adminEvent = new AdminEvent();
        adminEvent.setOperationType(OperationType.CREATE);
        adminEvent.setResourceType(ResourceType.USER);

        provider.onEvent(adminEvent, false);

        verify(mockClient).sendAsync(anyString());
    }

    @Test
    void nonUserAdminEventIsSkipped() {
        AdminEvent adminEvent = new AdminEvent();
        adminEvent.setOperationType(OperationType.CREATE);
        adminEvent.setResourceType(ResourceType.GROUP);

        provider.onEvent(adminEvent, false);

        verify(mockClient, never()).sendAsync(anyString());
    }

    @Test
    void nonMonitoredAdminOpIsSkipped() {
        AdminEvent adminEvent = new AdminEvent();
        adminEvent.setOperationType(OperationType.ACTION);
        adminEvent.setResourceType(ResourceType.USER);

        provider.onEvent(adminEvent, false);

        verify(mockClient, never()).sendAsync(anyString());
    }

    @Test
    void adminErrorEventIsSkipped() {
        AdminEvent adminEvent = new AdminEvent();
        adminEvent.setOperationType(OperationType.UPDATE);
        adminEvent.setResourceType(ResourceType.USER);
        adminEvent.setError("some_error");

        provider.onEvent(adminEvent, false);

        verify(mockClient, never()).sendAsync(anyString());
    }
}
