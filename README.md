# Keycloak Webhook Event Listener

A production-ready Keycloak SPI (Service Provider Interface) event listener that sends webhooks with HMAC-SHA256 signatures for user events and admin operations.

## Features

✅ **Secure Authentication**: HMAC-SHA256 signature verification  
✅ **Async Processing**: Non-blocking webhook delivery  
✅ **Automatic Retries**: Configurable retry logic with exponential backoff  
✅ **Event Filtering**: Only sends webhooks for relevant events (LOGIN, REGISTER, etc.)  
✅ **Customizable Payload**: Include/exclude user groups and attributes  
✅ **Production Ready**: Comprehensive error handling and logging  
✅ **Zero Dependencies**: Self-contained JAR (except Keycloak APIs)  

## Supported Events

### User Events
- `LOGIN` - User successfully logged in
- `REGISTER` - New user registered
- `LOGOUT` - User logged out
- `UPDATE_EMAIL` - User email updated
- `UPDATE_PROFILE` - User profile updated
- `VERIFY_EMAIL` - Email verification completed

### Admin Events
- `CREATE` - User created by admin
- `UPDATE` - User updated by admin
- `DELETE` - User deleted by admin

## Installation

### 1. Build the JAR

```bash
mvn clean package
```

This creates `target/keycloak-webhook-listener-1.0.0.jar`

### 2. Deploy to Keycloak

Copy the JAR to Keycloak's providers directory:

```bash
# For standalone Keycloak
cp target/keycloak-webhook-listener-1.0.0.jar /opt/keycloak/providers/

# For Docker
COPY target/keycloak-webhook-listener-1.0.0.jar /opt/keycloak/providers/
```

### 3. Configure Environment Variables

Set these environment variables in your Keycloak deployment:

```bash
# Required
WEBHOOK_URL=https://your-api.com/api/v1/auth/keycloak/webhook
WEBHOOK_SECRET=your-secret-key-here

# Optional (with defaults)
WEBHOOK_MAX_RETRIES=3
WEBHOOK_TIMEOUT_SECONDS=10
WEBHOOK_INCLUDE_GROUPS=true
WEBHOOK_INCLUDE_ATTRIBUTES=true
```

### 4. Enable the Event Listener

#### Via Keycloak Admin Console:
1. Navigate to **Realm Settings** → **Events**
2. Click **Event Listeners** tab
3. Add `webhook_event_listener` to the list
4. Save changes

#### Via Realm JSON:
```json
{
  "eventsEnabled": true,
  "eventsListeners": ["jboss-logging", "webhook_event_listener"],
  "adminEventsEnabled": true,
  "adminEventsDetailsEnabled": true
}
```

### 5. Rebuild Keycloak (if using Docker)

```bash
/opt/keycloak/bin/kc.sh build
```

## Webhook Payload Format

### User Event Example (LOGIN)

```json
{
  "event": "LOGIN",
  "realmId": "master",
  "clientId": "my-client",
  "ipAddress": "192.168.1.100",
  "timestamp": 1702345678000,
  "iat": 1702345678,
  "exp": 1702349278,
  "session_state": "abc123-def456",
  "provider": "google",
  "details": {
    "identity_provider": "google",
    "identity_provider_identity": "user@gmail.com"
  },
  "user": {
    "id": "user-uuid-123",
    "username": "john.doe",
    "email": "john.doe@example.com",
    "email_verified": true,
    "given_name": "John",
    "family_name": "Doe",
    "name": "John Doe",
    "enabled": true,
    "created_timestamp": 1702000000000,
    "groups": ["developers", "admins"],
    "attributes": {
      "phone": "+1234567890",
      "department": "Engineering"
    }
  }
}
```

### Admin Event Example (CREATE)

```json
{
  "type": "ADMIN_EVENT",
  "operationType": "CREATE",
  "realmId": "master",
  "clientId": "admin-cli",
  "userId": "admin-uuid-456",
  "ipAddress": "192.168.1.101",
  "resourceType": "USER",
  "resourcePath": "users/user-uuid-789",
  "timestamp": 1702345678000,
  "iat": 1702345678,
  "exp": 1702349278,
  "user": {
    "id": "admin-uuid-456",
    "username": "admin",
    "email": "admin@example.com",
    "email_verified": true
  }
}
```

## HMAC Signature Verification

The webhook includes an `X-Keycloak-Signature` header with HMAC-SHA256 signature (hex-encoded).

### Verification Example (Go)

```go
import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
)

func verifyHMAC(payload []byte, receivedSignature string, secret string) bool {
    mac := hmac.New(sha256.New, []byte(secret))
    mac.Write(payload)
    expectedSignature := hex.EncodeToString(mac.Sum(nil))
    return hmac.Equal([]byte(expectedSignature), []byte(receivedSignature))
}
```

### Verification Example (Node.js)

```javascript
const crypto = require('crypto');

function verifyHMAC(payload, receivedSignature, secret) {
  const hmac = crypto.createHmac('sha256', secret);
  hmac.update(payload);
  const expectedSignature = hmac.digest('hex');
  return crypto.timingSafeEqual(
    Buffer.from(expectedSignature), 
    Buffer.from(receivedSignature)
  );
}
```

## Configuration Options

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `WEBHOOK_URL` | Target webhook endpoint URL | *Required* |
| `WEBHOOK_SECRET` | Secret key for HMAC signature | *Required* |
| `WEBHOOK_MAX_RETRIES` | Number of retry attempts on failure | `3` |
| `WEBHOOK_TIMEOUT_SECONDS` | HTTP request timeout in seconds | `10` |
| `WEBHOOK_INCLUDE_GROUPS` | Include user groups in payload | `true` |
| `WEBHOOK_INCLUDE_ATTRIBUTES` | Include user attributes in payload | `true` |

### Alternative Environment Variables

For backward compatibility, these are also supported:
- `KEYCLOAK_WEBHOOK_URL` (fallback for `WEBHOOK_URL`)
- `KEYCLOAK_WEBHOOK_SECRET` (fallback for `WEBHOOK_SECRET`)

## Docker Integration

### Dockerfile Example

```dockerfile
FROM quay.io/keycloak/keycloak:24.0.1

# Copy custom event listener
COPY target/keycloak-webhook-listener-1.0.0.jar /opt/keycloak/providers/

# Set environment variables
ENV WEBHOOK_URL=https://your-api.com/webhooks/keycloak \
    WEBHOOK_SECRET=your-secret-here \
    WEBHOOK_MAX_RETRIES=3

# Pre-build Keycloak for faster startup
RUN /opt/keycloak/bin/kc.sh build

# Start Keycloak
CMD ["/opt/keycloak/bin/kc.sh", "start"]
```

### Docker Compose Example

```yaml
services:
  keycloak:
    image: your-registry/keycloak-with-webhook:latest
    environment:
      WEBHOOK_URL: https://identity-service.example.com/api/v1/auth/keycloak/webhook
      WEBHOOK_SECRET: ${WEBHOOK_SECRET}
      WEBHOOK_MAX_RETRIES: 3
      KC_DB: postgres
      KC_DB_URL: jdbc:postgresql://postgres:5432/keycloak
      KC_DB_USERNAME: keycloak
      KC_DB_PASSWORD: ${DB_PASSWORD}
    ports:
      - "8080:8080"
```

## Kubernetes/Helm Integration

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: keycloak
spec:
  template:
    spec:
      containers:
      - name: keycloak
        image: your-registry/keycloak-with-webhook:latest
        env:
        - name: WEBHOOK_URL
          value: "https://identity-service/api/v1/auth/keycloak/webhook"
        - name: WEBHOOK_SECRET
          valueFrom:
            secretKeyRef:
              name: keycloak-webhook-secret
              key: webhook-secret
```

## Logging

The event listener provides detailed logging at different levels:

- **INFO**: Event processing and webhook delivery status
- **DEBUG**: Payload details and configuration
- **WARN**: Retry attempts and configuration issues
- **ERROR**: Delivery failures and exceptions

View logs:
```bash
# Docker
docker logs keycloak-container

# Kubernetes
kubectl logs deployment/keycloak -f

# Standalone
tail -f /opt/keycloak/data/log/keycloak.log
```

## Troubleshooting

### Webhook not firing

1. **Check event listener is registered:**
   ```bash
   # Check Keycloak logs for initialization message
   grep "Webhook Event Listener configured" keycloak.log
   ```

2. **Verify environment variables:**
   ```bash
   # In container
   env | grep WEBHOOK
   ```

3. **Check realm events configuration:**
   - Go to Realm Settings → Events
   - Ensure `webhook_event_listener` is in the Event Listeners list
   - Verify Events are enabled

4. **Check logs for errors:**
   ```bash
   grep -i "webhook" keycloak.log | grep -i "error\|warn"
   ```

### Webhook delivery fails

1. **Check endpoint is accessible from Keycloak:**
   ```bash
   # Inside Keycloak container
   curl -X POST https://your-webhook-url \
     -H "Content-Type: application/json" \
     -d '{"test": "connectivity"}'
   ```

2. **Verify HMAC signature format:**
   - The listener sends hex-encoded HMAC-SHA256
   - Header: `X-Keycloak-Signature: <hex-string>`

3. **Check retry configuration:**
   - Increase `WEBHOOK_MAX_RETRIES` if experiencing transient failures
   - Check network connectivity and DNS resolution

## Development

### Build from Source

```bash
# Clone repository
git clone https://github.com/pragnya-analytics/keycloak-webhook.git
cd keycloak-webhook

# Build
mvn clean package

# Run tests
mvn test
```

### Testing Locally

```bash
# Start Keycloak with custom listener
docker run -d \
  -e WEBHOOK_URL=http://host.docker.internal:8081/webhook \
  -e WEBHOOK_SECRET=test-secret \
  -p 8080:8080 \
  -v $(pwd)/target/keycloak-webhook-listener-1.0.0.jar:/opt/keycloak/providers/webhook.jar \
  quay.io/keycloak/keycloak:24.0.1 \
  start-dev
```

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Support

For issues and questions:
- GitHub Issues: https://github.com/pragnya-analytics/keycloak-webhook/issues
- Email: support@pragnyaanalytics.com

## Author

**Pragnya Analytics**  
https://pragnyaanalytics.com
