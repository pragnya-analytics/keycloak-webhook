package com.pragnya.keycloak.provider;

import com.google.gson.JsonObject;
import com.pragnya.keycloak.webhook.WebhookClient;
import com.pragnya.keycloak.webhook.WebhookConfig;
import com.pragnya.keycloak.webhook.WebhookPayload;
import org.jboss.logging.Logger;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.OperationType;
import org.keycloak.models.KeycloakSession;

import java.util.Set;

/**
 * Keycloak Event Listener that sends webhooks for configured events
 */
public class WebhookEventListenerProvider implements EventListenerProvider {
    private static final Logger logger = Logger.getLogger(WebhookEventListenerProvider.class);
    
    // Events we want to send webhooks for
    private static final Set<EventType> MONITORED_EVENTS = Set.of(
        EventType.LOGIN,
        EventType.REGISTER,
        EventType.LOGOUT,
        EventType.UPDATE_EMAIL,
        EventType.UPDATE_PROFILE,
        EventType.VERIFY_EMAIL
    );
    
    // Admin operations we want to send webhooks for
    private static final Set<OperationType> MONITORED_ADMIN_OPS = Set.of(
        OperationType.CREATE,
        OperationType.UPDATE,
        OperationType.DELETE
    );
    
    private final KeycloakSession session;
    private final WebhookClient client;
    private final WebhookConfig config;
    
    public WebhookEventListenerProvider(KeycloakSession session, WebhookClient client, 
                                       WebhookConfig config) {
        this.session = session;
        this.client = client;
        this.config = config;
    }
    
    @Override
    public void onEvent(Event event) {
        // Filter events we care about
        if (!MONITORED_EVENTS.contains(event.getType())) {
            logger.tracef("Skipping non-monitored event: %s", event.getType());
            return;
        }
        
        // Don't send webhooks for error events
        if (event.getError() != null) {
            logger.debugf("Skipping error event: %s - %s", event.getType(), event.getError());
            return;
        }
        
        try {
            logger.infof("Processing event: type=%s, realm=%s, user=%s", 
                        event.getType(), event.getRealmId(), event.getUserId());
            
            // Build payload
            JsonObject payload = WebhookPayload.fromEvent(
                event, 
                session, 
                config.isIncludeUserGroups(), 
                config.isIncludeUserAttributes()
            );
            
            String jsonPayload = payload.toString();
            logger.debugf("Webhook payload: %s", jsonPayload);
            
            // Send webhook asynchronously
            client.sendAsync(jsonPayload).thenAccept(success -> {
                if (success) {
                    logger.infof("Webhook sent successfully for event: %s", event.getType());
                } else {
                    logger.errorf("Webhook delivery failed for event: %s", event.getType());
                }
            }).exceptionally(ex -> {
                logger.errorf(ex, "Webhook exception for event: %s", event.getType());
                return null;
            });
            
        } catch (Exception e) {
            logger.errorf(e, "Failed to process event: %s", event.getType());
        }
    }
    
    @Override
    public void onEvent(AdminEvent adminEvent, boolean includeRepresentation) {
        // Filter admin operations we care about
        if (!MONITORED_ADMIN_OPS.contains(adminEvent.getOperationType())) {
            logger.tracef("Skipping non-monitored admin operation: %s", 
                         adminEvent.getOperationType());
            return;
        }
        
        // Only process user-related admin events
        if (adminEvent.getResourceType() == null || 
            !adminEvent.getResourceType().toString().equals("USER")) {
            logger.tracef("Skipping non-user admin event: %s", 
                         adminEvent.getResourceType());
            return;
        }
        
        // Don't send webhooks for error events
        if (adminEvent.getError() != null) {
            logger.debugf("Skipping admin error event: %s - %s", 
                         adminEvent.getOperationType(), adminEvent.getError());
            return;
        }
        
        try {
            logger.infof("Processing admin event: operation=%s, resource=%s, path=%s", 
                        adminEvent.getOperationType(), 
                        adminEvent.getResourceType(),
                        adminEvent.getResourcePath());
            
            // Build payload
            JsonObject payload = WebhookPayload.fromAdminEvent(
                adminEvent, 
                session,
                config.isIncludeUserGroups(), 
                config.isIncludeUserAttributes()
            );
            
            String jsonPayload = payload.toString();
            logger.debugf("Admin webhook payload: %s", jsonPayload);
            
            // Send webhook asynchronously
            client.sendAsync(jsonPayload).thenAccept(success -> {
                if (success) {
                    logger.infof("Admin webhook sent successfully: %s", 
                               adminEvent.getOperationType());
                } else {
                    logger.errorf("Admin webhook delivery failed: %s", 
                                adminEvent.getOperationType());
                }
            }).exceptionally(ex -> {
                logger.errorf(ex, "Admin webhook exception: %s", 
                            adminEvent.getOperationType());
                return null;
            });
            
        } catch (Exception e) {
            logger.errorf(e, "Failed to process admin event: %s", 
                        adminEvent.getOperationType());
        }
    }
    
    @Override
    public void close() {
        // Nothing to clean up
    }
}
