package com.pragnya.keycloak.webhook;

import com.google.gson.JsonObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.events.Event;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.AuthDetails;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;

import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class WebhookPayloadTest {

    private KeycloakSession session;
    private RealmModel realm;
    private UserModel user;
    private UserProvider userProvider;

    @BeforeEach
    void setUp() {
        session = mock(KeycloakSession.class);
        realm = mock(RealmModel.class);
        userProvider = mock(UserProvider.class);
        user = mock(UserModel.class);

        KeycloakContext context = mock(KeycloakContext.class);
        when(session.getContext()).thenReturn(context);
        when(context.getRealm()).thenReturn(realm);
        when(session.users()).thenReturn(userProvider);

        when(user.getId()).thenReturn("user-123");
        when(user.getUsername()).thenReturn("testuser");
        when(user.getEmail()).thenReturn("test@example.com");
        when(user.isEmailVerified()).thenReturn(true);
        when(user.getFirstName()).thenReturn("Test");
        when(user.getLastName()).thenReturn("User");
        when(user.isEnabled()).thenReturn(true);
        when(user.getCreatedTimestamp()).thenReturn(1700000000000L);
        when(user.getGroupsStream()).thenReturn(Stream.empty());
        when(user.getAttributes()).thenReturn(Map.of());
    }

    @Test
    void fromEventIncludesEventMetadata() {
        when(userProvider.getUserById(realm, "user-1")).thenReturn(null);

        Event event = new Event();
        event.setType(EventType.LOGIN);
        event.setRealmId("realm-abc");
        event.setUserId("user-1");
        event.setTime(1700000000L);

        JsonObject payload = WebhookPayload.fromEvent(event, session, false, false);

        assertEquals("LOGIN", payload.get("event").getAsString());
        assertEquals("realm-abc", payload.get("realmId").getAsString());
        assertTrue(payload.has("timestamp"));
    }

    @Test
    void fromEventIncludesUserObject() {
        when(userProvider.getUserById(realm, "user-1")).thenReturn(user);

        Event event = new Event();
        event.setType(EventType.REGISTER);
        event.setRealmId("realm-abc");
        event.setUserId("user-1");

        JsonObject payload = WebhookPayload.fromEvent(event, session, false, false);

        assertTrue(payload.has("user"));
        JsonObject userObj = payload.getAsJsonObject("user");
        assertEquals("user-123", userObj.get("id").getAsString());
        assertEquals("testuser", userObj.get("username").getAsString());
    }

    @Test
    void fromEventExcludesGroupsWhenDisabled() {
        GroupModel group = mock(GroupModel.class);
        when(group.getName()).thenReturn("teachers");
        when(user.getGroupsStream()).thenReturn(Stream.of(group));
        when(userProvider.getUserById(realm, "user-1")).thenReturn(user);

        Event event = new Event();
        event.setType(EventType.LOGIN);
        event.setUserId("user-1");

        JsonObject payload = WebhookPayload.fromEvent(event, session, false, false);
        JsonObject userObj = payload.getAsJsonObject("user");

        assertFalse(userObj.has("groups"));
    }

    @Test
    void fromEventIncludesGroupsWhenEnabled() {
        GroupModel group = mock(GroupModel.class);
        when(group.getName()).thenReturn("teachers");
        when(user.getGroupsStream()).thenReturn(Stream.of(group));
        when(userProvider.getUserById(realm, "user-1")).thenReturn(user);

        Event event = new Event();
        event.setType(EventType.LOGIN);
        event.setUserId("user-1");

        JsonObject payload = WebhookPayload.fromEvent(event, session, true, false);
        JsonObject userObj = payload.getAsJsonObject("user");

        assertTrue(userObj.has("groups"));
        assertEquals("teachers", userObj.getAsJsonArray("groups").get(0).getAsString());
    }

    @Test
    void fromEventIncludesAttributesWhenEnabled() {
        when(user.getAttributes()).thenReturn(Map.of("grade", List.of("10")));
        when(user.getGroupsStream()).thenReturn(Stream.empty());
        when(userProvider.getUserById(realm, "user-1")).thenReturn(user);

        Event event = new Event();
        event.setType(EventType.LOGIN);
        event.setUserId("user-1");

        JsonObject payload = WebhookPayload.fromEvent(event, session, false, true);
        JsonObject userObj = payload.getAsJsonObject("user");

        assertTrue(userObj.has("attributes"));
        assertEquals("10", userObj.getAsJsonObject("attributes").get("grade").getAsString());
    }

    @Test
    void fromAdminEventIncludesOperationType() {
        AdminEvent adminEvent = new AdminEvent();
        adminEvent.setOperationType(OperationType.CREATE);
        adminEvent.setResourceType(ResourceType.USER);
        adminEvent.setResourcePath("users/user-123");

        JsonObject payload = WebhookPayload.fromAdminEvent(adminEvent, session, false, false);

        assertEquals("ADMIN_EVENT", payload.get("type").getAsString());
        assertEquals("CREATE", payload.get("operationType").getAsString());
        assertEquals("USER", payload.get("resourceType").getAsString());
        assertEquals("users/user-123", payload.get("resourcePath").getAsString());
    }

    @Test
    void fromAdminEventIncludesAuthDetails() {
        AuthDetails auth = new AuthDetails();
        auth.setRealmId("realm-1");
        auth.setUserId("admin-user");
        auth.setClientId("admin-cli");

        when(userProvider.getUserById(realm, "admin-user")).thenReturn(null);

        AdminEvent adminEvent = new AdminEvent();
        adminEvent.setOperationType(OperationType.UPDATE);
        adminEvent.setResourceType(ResourceType.USER);
        adminEvent.setAuthDetails(auth);

        JsonObject payload = WebhookPayload.fromAdminEvent(adminEvent, session, false, false);

        assertEquals("realm-1", payload.get("realmId").getAsString());
        assertEquals("admin-user", payload.get("userId").getAsString());
    }

    @Test
    void fromEventWithNoUserIdProducesNoUserField() {
        Event event = new Event();
        event.setType(EventType.LOGOUT);

        JsonObject payload = WebhookPayload.fromEvent(event, session, false, false);

        assertNull(payload.get("user"));
    }
}
