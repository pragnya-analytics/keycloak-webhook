package com.pragnya.keycloak.webhook;

import com.google.gson.JsonObject;
import org.keycloak.events.Event;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Builds webhook payloads from Keycloak events
 */
public class WebhookPayload {
    
    /**
     * Build payload from user event (LOGIN, REGISTER, etc.)
     */
    public static JsonObject fromEvent(Event event, KeycloakSession session, 
                                      boolean includeGroups, boolean includeAttributes) {
        JsonObject payload = new JsonObject();
        
        // Event metadata
        if (event.getType() != null) {
            payload.addProperty("event", event.getType().toString());
        }
        if (event.getRealmId() != null) {
            payload.addProperty("realmId", event.getRealmId());
        }
        if (event.getClientId() != null) {
            payload.addProperty("clientId", event.getClientId());
        }
        if (event.getIpAddress() != null) {
            payload.addProperty("ipAddress", event.getIpAddress());
        }
        if (event.getError() != null) {
            payload.addProperty("error", event.getError());
        }
        
        // Timestamps
        payload.addProperty("timestamp", event.getTime());
        payload.addProperty("iat", Instant.now().getEpochSecond());
        payload.addProperty("exp", Instant.now().plusSeconds(3600).getEpochSecond());
        
        // Session state
        if (event.getSessionId() != null) {
            payload.addProperty("session_state", event.getSessionId());
        }
        
        // Event details
        if (event.getDetails() != null && !event.getDetails().isEmpty()) {
            JsonObject details = new JsonObject();
            for (Map.Entry<String, String> entry : event.getDetails().entrySet()) {
                if (entry.getValue() != null) {
                    details.addProperty(entry.getKey(), entry.getValue());
                    
                    // Extract provider from identity_provider_identity
                    if ("identity_provider".equals(entry.getKey())) {
                        payload.addProperty("provider", entry.getValue());
                    }
                }
            }
            payload.add("details", details);
        }
        
        // User information
        if (event.getUserId() != null) {
            RealmModel realm = session.getContext().getRealm();
            UserModel user = session.users().getUserById(realm, event.getUserId());
            
            if (user != null) {
                JsonObject userObj = buildUserObject(user, includeGroups, includeAttributes);
                payload.add("user", userObj);
            }
        }
        
        return payload;
    }
    
    /**
     * Build payload from admin event (CREATE, UPDATE, DELETE)
     */
    public static JsonObject fromAdminEvent(AdminEvent adminEvent, KeycloakSession session,
                                           boolean includeGroups, boolean includeAttributes) {
        JsonObject payload = new JsonObject();
        
        // Event metadata
        payload.addProperty("type", "ADMIN_EVENT");
        
        if (adminEvent.getOperationType() != null) {
            payload.addProperty("operationType", adminEvent.getOperationType().toString());
        }
        
        if (adminEvent.getAuthDetails() != null) {
            if (adminEvent.getAuthDetails().getRealmId() != null) {
                payload.addProperty("realmId", adminEvent.getAuthDetails().getRealmId());
            }
            if (adminEvent.getAuthDetails().getClientId() != null) {
                payload.addProperty("clientId", adminEvent.getAuthDetails().getClientId());
            }
            if (adminEvent.getAuthDetails().getUserId() != null) {
                payload.addProperty("userId", adminEvent.getAuthDetails().getUserId());
            }
            if (adminEvent.getAuthDetails().getIpAddress() != null) {
                payload.addProperty("ipAddress", adminEvent.getAuthDetails().getIpAddress());
            }
        }
        
        if (adminEvent.getResourceType() != null) {
            payload.addProperty("resourceType", adminEvent.getResourceType().toString());
        }
        if (adminEvent.getResourcePath() != null) {
            payload.addProperty("resourcePath", adminEvent.getResourcePath());
        }
        if (adminEvent.getError() != null) {
            payload.addProperty("error", adminEvent.getError());
        }
        
        // Timestamps
        payload.addProperty("timestamp", adminEvent.getTime());
        payload.addProperty("iat", Instant.now().getEpochSecond());
        payload.addProperty("exp", Instant.now().plusSeconds(3600).getEpochSecond());
        
        // User information if this is a user-related admin event
        if (adminEvent.getAuthDetails() != null && 
            adminEvent.getAuthDetails().getUserId() != null) {
            RealmModel realm = session.getContext().getRealm();
            UserModel user = session.users().getUserById(realm, 
                                                         adminEvent.getAuthDetails().getUserId());
            
            if (user != null) {
                JsonObject userObj = buildUserObject(user, includeGroups, includeAttributes);
                payload.add("user", userObj);
            }
        }
        
        return payload;
    }
    
    /**
     * Build user object with optional groups and attributes
     */
    private static JsonObject buildUserObject(UserModel user, boolean includeGroups, 
                                             boolean includeAttributes) {
        JsonObject userObj = new JsonObject();
        
        // Basic user info
        userObj.addProperty("id", user.getId());
        if (user.getUsername() != null) {
            userObj.addProperty("username", user.getUsername());
        }
        if (user.getEmail() != null) {
            userObj.addProperty("email", user.getEmail());
        }
        userObj.addProperty("email_verified", user.isEmailVerified());
        
        if (user.getFirstName() != null) {
            userObj.addProperty("given_name", user.getFirstName());
        }
        if (user.getLastName() != null) {
            userObj.addProperty("family_name", user.getLastName());
        }
        
        // Full name
        String fullName = buildFullName(user.getFirstName(), user.getLastName());
        if (fullName != null) {
            userObj.addProperty("name", fullName);
        }
        
        userObj.addProperty("enabled", user.isEnabled());
        
        if (user.getCreatedTimestamp() != null) {
            userObj.addProperty("created_timestamp", user.getCreatedTimestamp());
        }
        
        // Optional: Groups
        if (includeGroups) {
            List<String> groups = user.getGroupsStream()
                .map(GroupModel::getName)
                .collect(Collectors.toList());
            
            if (!groups.isEmpty()) {
                com.google.gson.JsonArray groupsArray = new com.google.gson.JsonArray();
                groups.forEach(groupsArray::add);
                userObj.add("groups", groupsArray);
            }
        }
        
        // Optional: Attributes
        if (includeAttributes && user.getAttributes() != null && !user.getAttributes().isEmpty()) {
            JsonObject attributesObj = new JsonObject();
            for (Map.Entry<String, List<String>> entry : user.getAttributes().entrySet()) {
                if (entry.getValue() != null && !entry.getValue().isEmpty()) {
                    if (entry.getValue().size() == 1) {
                        attributesObj.addProperty(entry.getKey(), entry.getValue().get(0));
                    } else {
                        com.google.gson.JsonArray attrArray = new com.google.gson.JsonArray();
                        entry.getValue().forEach(attrArray::add);
                        attributesObj.add(entry.getKey(), attrArray);
                    }
                }
            }
            if (attributesObj.size() > 0) {
                userObj.add("attributes", attributesObj);
            }
        }
        
        return userObj;
    }
    
    private static String buildFullName(String firstName, String lastName) {
        if (firstName != null && lastName != null) {
            return firstName + " " + lastName;
        } else if (firstName != null) {
            return firstName;
        } else if (lastName != null) {
            return lastName;
        }
        return null;
    }
}
