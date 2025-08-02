# GitHub Webhook PR Review System

OpenHands includes a comprehensive GitHub webhook system that automatically reviews pull requests using AI. This system can detect new PRs, analyze code changes, flag issues, and post review comments back to GitHub.

## Features

- **Automatic PR Detection**: Listens for GitHub webhook events when PRs are opened, updated, or synchronized
- **AI-Powered Code Analysis**: Uses OpenHands AI agents to analyze code changes and identify potential issues
- **Security**: Validates webhook signatures and restricts access to configured repositories
- **Configurable**: Supports various configuration options through environment variables and UI settings
- **Review Comments**: Posts detailed review comments back to GitHub PRs
- **Auto-fix Support**: Optional automatic fix generation with PR creation (future enhancement)

## Configuration

### Environment Variables

The webhook system can be configured using the following environment variables:

- `WEBHOOK_SECRET`: Secret for validating GitHub webhook signatures
- `WEBHOOK_ALLOWED_REPOS`: Comma-separated list of repositories allowed to trigger reviews (e.g., "user/repo1,org/repo2")
- `WEBHOOK_AUTO_FIX`: Enable/disable automatic fix generation (true/false)

### UI Settings

Webhook settings can also be configured through the OpenHands web interface:

1. Navigate to Settings in the OpenHands UI
2. Scroll to the "Webhook Settings" section
3. Configure:
   - **Webhook Secret**: Secret key for validating GitHub webhooks
   - **Allowed Repositories**: Comma-separated list of repositories (leave empty to allow all)
   - **Auto-fix Enabled**: Whether to enable automatic fix generation

## Setup Instructions

### 1. Configure OpenHands

Set up your webhook settings either through environment variables or the UI:

```bash
export WEBHOOK_SECRET="your-webhook-secret-here"
export WEBHOOK_ALLOWED_REPOS="your-username/your-repo"
export WEBHOOK_AUTO_FIX="false"
```

Or configure through the UI as described above.

### 2. Start OpenHands Server

Start the OpenHands server with webhook support:

```bash
poetry run python -m openhands.server.listen --port 3000 --host 0.0.0.0
```

### 3. Configure GitHub Webhook

1. Go to your GitHub repository settings
2. Navigate to "Webhooks" section
3. Click "Add webhook"
4. Configure:
   - **Payload URL**: `https://your-openhands-server.com/api/webhook/github`
   - **Content type**: `application/json`
   - **Secret**: Use the same secret you configured in OpenHands
   - **Events**: Select "Pull requests" and "Pull request reviews"
5. Click "Add webhook"

### 4. Test the Setup

1. Create a test pull request in your configured repository
2. Check the webhook health endpoint: `GET /api/webhook/health`
3. Verify that OpenHands receives the webhook and starts a review

## API Endpoints

### Webhook Health Check

```http
GET /api/webhook/health
```

Returns the current status of the webhook system:

```json
{
  "status": "healthy",
  "webhook_secret_configured": true,
  "allowed_repos_configured": true,
  "auto_fix_enabled": false
}
```

### GitHub Webhook Handler

```http
POST /api/webhook/github
```

Handles incoming GitHub webhook events. This endpoint:
- Validates the webhook signature
- Checks if the repository is allowed
- Processes PR events (opened, synchronize, reopened)
- Initiates AI-powered code review

## How It Works

### 1. Webhook Reception

When a PR event occurs in GitHub:
1. GitHub sends a webhook to the configured URL
2. OpenHands validates the webhook signature using the configured secret
3. The system checks if the repository is in the allowed list
4. Valid PR events (opened, synchronize, reopened) are processed

### 2. PR Analysis

For valid PR events:
1. OpenHands fetches the PR details and changed files from GitHub
2. An AI agent analyzes the code changes
3. The agent identifies potential issues, bugs, or improvements
4. Review comments are generated with specific line-by-line feedback

### 3. Review Posting

The generated review is posted back to GitHub:
1. Comments are posted on specific lines of changed code
2. A summary review is provided at the PR level
3. Issues are categorized by severity and type

## Security Considerations

- **Webhook Signatures**: All webhooks are validated using HMAC-SHA256 signatures
- **Repository Allowlist**: Only configured repositories can trigger reviews
- **Secret Management**: Webhook secrets are stored securely and never exposed in logs
- **Rate Limiting**: The system respects GitHub API rate limits

## Troubleshooting

### Common Issues

1. **Webhook not triggering**:
   - Check that the webhook URL is correct
   - Verify the webhook secret matches
   - Ensure the repository is in the allowed list

2. **Authentication errors**:
   - Verify GitHub token has proper permissions
   - Check that the token is not expired

3. **Review not posting**:
   - Check OpenHands logs for errors
   - Verify GitHub API permissions
   - Ensure the PR is not from a fork (if restrictions apply)

### Health Check

Use the health endpoint to verify configuration:

```bash
curl https://your-openhands-server.com/api/webhook/health
```

### Logs

Check OpenHands server logs for detailed webhook processing information:

```bash
# Look for webhook-related log entries
grep -i webhook server.log
```

## Testing

### Unit Tests

Run the webhook unit tests:

```bash
poetry run pytest tests/unit/test_webhook.py -v
```

### Integration Testing

1. Set up a test repository with the webhook configured
2. Create a test PR with some code changes
3. Verify that OpenHands receives the webhook and processes it
4. Check that review comments are posted to the PR

### Manual Testing

You can manually test webhook functionality using tools like ngrok for local development:

1. Start OpenHands locally
2. Use ngrok to expose your local server: `ngrok http 3000`
3. Configure GitHub webhook to use the ngrok URL
4. Create test PRs to verify functionality

## Future Enhancements

- **Automatic Fix Generation**: Generate and submit fix PRs for identified issues
- **GitLab/Bitbucket Support**: Extend webhook support to other Git providers
- **Custom Review Rules**: Configure custom rules and checks for different repositories
- **Review Templates**: Customizable review comment templates
- **Integration with CI/CD**: Integrate with existing CI/CD pipelines
- **Metrics and Analytics**: Track review effectiveness and system performance

## API Reference

For complete API documentation, see the OpenAPI schema available at `/docs` when running the OpenHands server.