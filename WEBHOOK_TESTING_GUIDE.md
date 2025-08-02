# GitHub Webhook PR Review System - Testing Guide

This guide provides comprehensive instructions for testing the GitHub webhook system for automated PR reviews in OpenHands.

## Overview

The webhook system enables automatic PR reviews when pull requests are opened or synchronized in configured GitHub repositories. The system includes:

- **UI Configuration**: Web-based settings interface for webhook configuration
- **Webhook Endpoint**: Secure endpoint for receiving GitHub webhook events
- **PR Review Service**: AI-powered code analysis and review generation
- **GitHub Integration**: Automatic posting of review comments back to GitHub

## Prerequisites

1. **OpenHands Installation**: Complete OpenHands setup with frontend and backend running
2. **GitHub Repository**: A GitHub repository where you have admin access
3. **GitHub Personal Access Token**: Token with `repo` and `pull_requests` permissions
4. **ngrok or Similar**: Tool for exposing local webhook endpoint to GitHub

## Configuration Steps

### 1. Start OpenHands

```bash
# Start the backend server
cd /workspace/project/OpenHands
poetry run python -m openhands.server.listen

# In another terminal, start the frontend (if not using built version)
cd /workspace/project/OpenHands/frontend
npm run dev
```

### 2. Configure Webhook Settings via UI

1. **Access Settings**: Navigate to OpenHands web interface and go to Settings
2. **Webhook Settings**: Click on "Webhook Settings" in the navigation menu
3. **Configure Settings**:
   - **Webhook Secret**: Enter a secure random string (e.g., `my-webhook-secret-123`)
   - **Allowed Repositories**: Enter repository names in format `owner/repo` (comma-separated for multiple)
     - Example: `myusername/test-repo` or `myusername/repo1,myusername/repo2`
     - Leave empty to allow all repositories
   - **Auto Fix**: Enable/disable automatic fix generation (experimental feature)
4. **Save Settings**: Click "Save Settings" to persist configuration

### 3. Set Up GitHub Personal Access Token

1. **Add Token**: In OpenHands settings, go to "Secrets" section
2. **GitHub Token**: Add your GitHub personal access token with key `GITHUB_TOKEN`
3. **Permissions Required**:
   - `repo` (full repository access)
   - `pull_requests` (read/write pull requests)

### 4. Expose Webhook Endpoint

Using ngrok (recommended for testing):

```bash
# Install ngrok if not already installed
# Download from https://ngrok.com/download

# Expose OpenHands server (default port 3000)
ngrok http 3000

# Note the HTTPS URL provided by ngrok (e.g., https://abc123.ngrok.io)
```

### 5. Configure GitHub Webhook

1. **Repository Settings**: Go to your GitHub repository → Settings → Webhooks
2. **Add Webhook**:
   - **Payload URL**: `https://your-ngrok-url.ngrok.io/api/webhook/github`
   - **Content Type**: `application/json`
   - **Secret**: Enter the same webhook secret you configured in OpenHands UI
   - **Events**: Select "Pull requests" (or "Send me everything" for testing)
   - **Active**: Ensure the webhook is active
3. **Save**: Click "Add webhook"

## Testing Scenarios

### Test 1: Basic Webhook Health Check

```bash
# Test the webhook health endpoint
curl -X GET "https://your-ngrok-url.ngrok.io/api/webhook/health"

# Expected response:
{
  "status": "healthy",
  "webhook_secret_configured": true,
  "allowed_repos_configured": true,
  "auto_fix_enabled": false
}
```

### Test 2: Create a Test Pull Request

1. **Create Branch**: In your test repository, create a new branch
2. **Make Changes**: Add/modify some code files
3. **Open PR**: Create a pull request from the new branch to main
4. **Monitor Logs**: Check OpenHands server logs for webhook processing
5. **Check GitHub**: Look for automated review comments on the PR

### Test 3: Repository Filtering

1. **Configure Specific Repo**: Set allowed repositories to a specific repo in UI
2. **Test Allowed Repo**: Create PR in the allowed repository → should be processed
3. **Test Blocked Repo**: Create PR in a different repository → should be ignored

### Test 4: Webhook Signature Validation

1. **Valid Signature**: Normal PR creation should work (GitHub signs with your secret)
2. **Invalid Signature**: Manual webhook calls without proper signature should be rejected

```bash
# Test invalid signature (should fail)
curl -X POST "https://your-ngrok-url.ngrok.io/api/webhook/github" \
  -H "Content-Type: application/json" \
  -H "X-GitHub-Event: pull_request" \
  -H "X-Hub-Signature-256: sha256=invalid" \
  -d '{"action": "opened"}'

# Expected: 401 Unauthorized
```

## Monitoring and Debugging

### Server Logs

Monitor OpenHands server logs for webhook processing:

```bash
# Look for webhook-related log messages
tail -f /path/to/openhands/logs/server.log | grep -i webhook
```

### GitHub Webhook Deliveries

1. **Repository Settings**: Go to Settings → Webhooks
2. **Recent Deliveries**: Click on your webhook to see delivery history
3. **Response Codes**:
   - `200`: Successful processing
   - `401`: Authentication/signature failure
   - `500`: Server error

### Common Issues and Solutions

#### Issue: Webhook Returns 401 Unauthorized

**Causes**:
- Incorrect webhook secret in GitHub or OpenHands
- Missing session API key (if required)

**Solutions**:
- Verify webhook secret matches in both GitHub and OpenHands UI
- Check server logs for authentication errors

#### Issue: Webhook Returns 500 Internal Server Error

**Causes**:
- Missing GitHub token in OpenHands secrets
- Invalid repository configuration
- Server-side errors

**Solutions**:
- Verify GitHub token is configured in OpenHands secrets
- Check server logs for detailed error messages
- Ensure repository names are in correct format

#### Issue: No Review Comments Posted

**Causes**:
- GitHub token lacks required permissions
- PR has no code changes to review
- AI service errors

**Solutions**:
- Verify GitHub token has `repo` and `pull_requests` permissions
- Check that PR contains actual code changes
- Monitor server logs for AI service errors

## Advanced Testing

### Load Testing

Test webhook performance with multiple simultaneous PRs:

```bash
# Create multiple PRs quickly to test concurrent processing
# Monitor server performance and response times
```

### Error Recovery Testing

1. **Network Failures**: Test webhook behavior during network issues
2. **GitHub API Limits**: Test behavior when GitHub API rate limits are hit
3. **Invalid Payloads**: Send malformed webhook payloads to test error handling

### Integration Testing

1. **Multiple Repositories**: Test with multiple repositories in allowlist
2. **Large PRs**: Test with PRs containing many files/changes
3. **Different PR Actions**: Test with PR synchronization, not just opening

## Security Considerations

1. **Webhook Secret**: Use a strong, unique secret for webhook validation
2. **Token Permissions**: Use minimal required GitHub token permissions
3. **Repository Access**: Carefully configure allowed repositories
4. **HTTPS Only**: Always use HTTPS for webhook endpoints in production
5. **Rate Limiting**: Monitor for potential abuse of webhook endpoint

## Production Deployment

For production deployment:

1. **Domain Setup**: Use a proper domain instead of ngrok
2. **SSL Certificate**: Ensure valid SSL certificate for HTTPS
3. **Monitoring**: Set up proper logging and monitoring
4. **Backup**: Configure backup for webhook settings and secrets
5. **Scaling**: Consider load balancing for high-traffic scenarios

## API Reference

### Webhook Endpoints

- `GET /api/webhook/health` - Health check endpoint
- `POST /api/webhook/github` - GitHub webhook receiver

### Settings API

- `GET /api/settings` - Get current settings
- `POST /api/settings` - Update settings

### Required Settings Fields

```typescript
interface WebhookSettings {
  webhook_secret: string;           // Secret for webhook validation
  webhook_allowed_repos: string;   // Comma-separated repository list
  webhook_auto_fix: boolean;       // Enable automatic fix generation
}
```

## Troubleshooting Commands

```bash
# Check webhook endpoint health
curl -X GET "http://localhost:3000/api/webhook/health"

# Test webhook signature validation
python3 -c "
import hmac
import hashlib
import json

secret = 'your-webhook-secret'
payload = {'test': 'data'}
payload_bytes = json.dumps(payload).encode('utf-8')
signature = hmac.new(secret.encode(), payload_bytes, hashlib.sha256).hexdigest()
print(f'Signature: sha256={signature}')
"

# Check OpenHands server status
curl -X GET "http://localhost:3000/api/health"

# Verify GitHub token permissions
curl -H "Authorization: token YOUR_GITHUB_TOKEN" \
  "https://api.github.com/user"
```

This comprehensive testing guide covers all aspects of the webhook system from setup to production deployment. Follow these steps to ensure your GitHub webhook PR review system is working correctly.