# GitHub Webhook Configuration for Automated PR Reviews

This document describes how to configure and use the GitHub webhook system for automated pull request reviews in OpenHands.

## Overview

The webhook system enables OpenHands to automatically review pull requests when they are opened or updated. The system:

1. Receives GitHub webhook events for pull requests
2. Validates webhook signatures for security
3. Filters requests based on configured repository allowlists
4. Initiates OpenHands conversations to analyze code changes
5. Uses the built-in code review microagent to provide structured feedback
6. Can optionally suggest fixes for identified issues

## Environment Variables

### Required Configuration

#### `WEBHOOK_SECRET`
- **Description**: Secret key used to validate GitHub webhook signatures
- **Required**: Yes
- **Example**: `WEBHOOK_SECRET=your-webhook-secret-here`
- **Security**: This should be a strong, randomly generated secret that matches the secret configured in your GitHub webhook settings

#### `WEBHOOK_ALLOWED_REPOS`
- **Description**: Comma-separated list of repositories allowed to trigger reviews
- **Required**: Yes
- **Format**: `owner/repo,owner2/repo2`
- **Example**: `WEBHOOK_ALLOWED_REPOS=myorg/backend,myorg/frontend,myuser/personal-project`
- **Security**: Only repositories in this list will be processed; all others will be ignored

#### `GITHUB_TOKEN`
- **Description**: GitHub personal access token or app token for API access
- **Required**: Yes
- **Permissions**: The token needs the following permissions:
  - `pull_requests:read` - To fetch PR details and diffs
  - `pull_requests:write` - To post review comments
  - `contents:read` - To access repository content
- **Example**: `GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx`

### Optional Configuration

#### `WEBHOOK_AUTO_FIX`
- **Description**: Enable automatic fix generation for identified issues
- **Required**: No
- **Default**: `false`
- **Values**: `true` or `false`
- **Example**: `WEBHOOK_AUTO_FIX=true`
- **Note**: When enabled, the AI may suggest specific code fixes in addition to identifying issues

## GitHub Webhook Setup

### 1. Create Webhook in GitHub

1. Go to your repository settings
2. Navigate to "Webhooks" section
3. Click "Add webhook"
4. Configure the webhook:
   - **Payload URL**: `https://your-openhands-instance.com/api/webhook/github`
   - **Content type**: `application/json`
   - **Secret**: Use the same value as your `WEBHOOK_SECRET` environment variable
   - **Events**: Select "Pull requests" only
   - **Active**: Check this box

### 2. Test Webhook

You can test your webhook configuration using the health endpoint:

```bash
curl https://your-openhands-instance.com/api/webhook/health
```

Expected response:
```json
{
  "status": "healthy",
  "webhook_secret_configured": true,
  "allowed_repos_configured": true,
  "auto_fix_enabled": false
}
```

## Supported Events

The webhook system currently handles the following GitHub events:

- **Pull Request Opened** (`pull_request.opened`): Triggers when a new PR is created
- **Pull Request Synchronized** (`pull_request.synchronize`): Triggers when a PR is updated with new commits

Other pull request events (closed, merged, etc.) are ignored.

## Review Process

When a supported event is received:

1. **Validation**: Webhook signature and repository allowlist are checked
2. **Data Extraction**: PR details and code diff are fetched from GitHub API
3. **Conversation Creation**: A new OpenHands conversation is initiated with:
   - Repository context
   - PR metadata (title, author, description)
   - Complete code diff
   - Code review instructions
4. **AI Analysis**: The code review microagent analyzes the changes for:
   - Style and formatting issues
   - Code clarity and readability problems
   - Security vulnerabilities and bug patterns
5. **Feedback Generation**: Structured feedback is generated with:
   - Specific line numbers
   - Issue descriptions
   - Improvement suggestions
   - Appropriate emoji indicators

## Security Considerations

### Webhook Signature Validation

All incoming webhooks are validated using HMAC-SHA256 signatures to ensure they originate from GitHub and haven't been tampered with.

### Repository Allowlist

Only repositories explicitly listed in `WEBHOOK_ALLOWED_REPOS` will be processed. This prevents unauthorized usage and potential abuse.

### Token Permissions

The GitHub token should follow the principle of least privilege, only granting the minimum permissions required for the review functionality.

## Troubleshooting

### Common Issues

1. **Webhook not triggering**:
   - Check that the repository is in the `WEBHOOK_ALLOWED_REPOS` list
   - Verify the webhook URL is correct and accessible
   - Ensure the webhook secret matches the `WEBHOOK_SECRET` environment variable

2. **Authentication errors**:
   - Verify the `GITHUB_TOKEN` is valid and has required permissions
   - Check token expiration date

3. **Review not posted**:
   - Check OpenHands logs for conversation creation errors
   - Verify the GitHub token has write permissions for pull requests

### Debugging

Enable debug logging to troubleshoot issues:

```bash
# Check webhook health
curl https://your-openhands-instance.com/api/webhook/health

# Monitor OpenHands logs for webhook events
tail -f /path/to/openhands/logs
```

### Log Messages

Key log messages to look for:

- `Processing PR review for {repo}#{pr_number}`: Webhook received and processing started
- `PR review conversation created: {conversation_id}`: Conversation successfully created
- `Repository not allowed: {repo}`: Repository not in allowlist
- `Invalid webhook signature`: Signature validation failed

## Example Configuration

Complete environment configuration example:

```bash
# Required
WEBHOOK_SECRET=your-super-secret-webhook-key-here
WEBHOOK_ALLOWED_REPOS=myorg/backend,myorg/frontend,myorg/mobile-app
GITHUB_TOKEN=ghp_your_github_token_here

# Optional
WEBHOOK_AUTO_FIX=true

# Standard OpenHands configuration
LLM_MODEL=gpt-4
LLM_API_KEY=your-openai-api-key
```

## Future Enhancements

Planned improvements include:

- **Multi-provider Support**: GitLab and Bitbucket webhook support
- **Automatic Fix PRs**: Generate and submit fix PRs for identified issues
- **Custom Review Rules**: Repository-specific review configurations
- **Review Templates**: Customizable review comment templates
- **Integration Testing**: Comprehensive test suite for webhook functionality
- **Metrics and Analytics**: Review statistics and performance metrics

## API Reference

### Webhook Endpoint

**POST** `/api/webhook/github`

Receives GitHub webhook events for pull request reviews.

**Headers:**
- `X-Hub-Signature-256`: GitHub webhook signature
- `X-GitHub-Event`: Event type (must be "pull_request")
- `Content-Type`: application/json

**Response:**
```json
{
  "status": "success|ignored|error",
  "message": "Description of the result",
  "review_id": "unique-review-identifier",
  "conversation_id": "openhands-conversation-id"
}
```

### Health Check Endpoint

**GET** `/api/webhook/health`

Returns webhook service health and configuration status.

**Response:**
```json
{
  "status": "healthy",
  "webhook_secret_configured": true,
  "allowed_repos_configured": true,
  "auto_fix_enabled": false
}
```