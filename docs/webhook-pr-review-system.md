# GitHub PR Review Webhook System

## Overview

The GitHub PR Review Webhook System enables OpenHands to automatically review pull requests when they are opened or updated. This system provides AI-powered code analysis, security checks, and improvement suggestions directly in your GitHub workflow.

## Features

### Core Functionality
- **Automatic PR Detection**: Responds to GitHub webhook events for new and updated pull requests
- **Security Validation**: HMAC-SHA256 signature verification for webhook authenticity
- **Repository Filtering**: Configurable allowlist to control which repositories are reviewed
- **AI-Powered Analysis**: Uses OpenHands' code review microagent for comprehensive analysis
- **Structured Feedback**: Provides categorized feedback with line-specific suggestions

### Code Review Categories
1. **Style and Formatting**
   - Inconsistent indentation and spacing
   - Unused imports or variables
   - Naming convention violations
   - Missing or malformed documentation

2. **Clarity and Readability**
   - Complex or deeply nested logic
   - Functions violating single responsibility principle
   - Poor naming that obscures intent
   - Missing inline documentation

3. **Security and Bug Patterns**
   - Unsanitized user input vulnerabilities
   - Hardcoded secrets or credentials
   - Cryptographic library misuse
   - Common programming pitfalls

## Architecture

```
GitHub PR Event → Webhook → OpenHands → AI Analysis → Conversation Creation
                     ↓
              Signature Validation
                     ↓
              Repository Filtering
                     ↓
              PR Data Extraction
                     ↓
              Code Review Analysis
```

### Components

1. **Webhook Handler** (`openhands/server/routes/webhook.py`)
   - Receives and validates GitHub webhook events
   - Filters events based on configuration
   - Initiates PR review process

2. **PR Reviewer Service** (`openhands/server/services/pr_reviewer.py`)
   - Fetches PR details and code diffs
   - Creates OpenHands conversations for analysis
   - Manages the review workflow

3. **Code Review Microagent** (`microagents/code-review.md`)
   - Provides structured analysis framework
   - Generates categorized feedback
   - Suggests specific improvements

## Configuration

### Environment Variables

#### Required
```bash
# Webhook signature validation secret
WEBHOOK_SECRET=your-webhook-secret-here

# Comma-separated list of allowed repositories
WEBHOOK_ALLOWED_REPOS=owner1/repo1,owner2/repo2

# GitHub API access token
GITHUB_TOKEN=ghp_your_github_token_here
```

#### Optional
```bash
# Enable automatic fix suggestions (default: false)
WEBHOOK_AUTO_FIX=true
```

### GitHub Token Permissions

The GitHub token requires the following permissions:
- `pull_requests:read` - Fetch PR details and diffs
- `pull_requests:write` - Post review comments
- `contents:read` - Access repository content

## Setup Instructions

### 1. Configure OpenHands

Set the required environment variables in your OpenHands deployment:

```bash
export WEBHOOK_SECRET="your-secure-random-secret"
export WEBHOOK_ALLOWED_REPOS="your-org/repo1,your-org/repo2"
export GITHUB_TOKEN="ghp_your_github_token"
export WEBHOOK_AUTO_FIX="true"  # Optional
```

### 2. Set Up GitHub Webhook

1. Navigate to your repository settings on GitHub
2. Go to "Webhooks" section
3. Click "Add webhook"
4. Configure:
   - **Payload URL**: `https://your-openhands-instance.com/api/webhook/github`
   - **Content type**: `application/json`
   - **Secret**: Same value as `WEBHOOK_SECRET`
   - **Events**: Select "Pull requests" only
   - **Active**: ✅ Enabled

### 3. Test Configuration

Use the provided test script:

```bash
python examples/webhook_test.py \
  --url https://your-openhands-instance.com \
  --repo your-org/your-repo \
  --secret your-webhook-secret
```

Or check the health endpoint:

```bash
curl https://your-openhands-instance.com/api/webhook/health
```

## Usage

### Automatic Review Process

1. **PR Creation/Update**: Developer creates or updates a pull request
2. **Webhook Trigger**: GitHub sends webhook event to OpenHands
3. **Validation**: OpenHands validates signature and repository allowlist
4. **Data Extraction**: PR details and code diff are fetched
5. **AI Analysis**: Code review microagent analyzes the changes
6. **Conversation Creation**: New OpenHands conversation is created with review context
7. **Review Generation**: AI provides structured feedback and suggestions

### Review Output Format

Reviews follow a structured format with emoji indicators:

```
[Line 42] 🔧 Style: Unused import 'os' should be removed
[Lines 78-85] 🔍 Readability: Complex nested logic should be refactored
[Line 102] 🔒 Security: SQL injection vulnerability - use parameterized queries
```

### Supported Events

- `pull_request.opened` - New PR created
- `pull_request.synchronize` - PR updated with new commits

Other PR events (closed, merged, etc.) are ignored.

## API Reference

### Webhook Endpoint

**POST** `/api/webhook/github`

Receives GitHub webhook events for pull request processing.

**Headers:**
- `X-Hub-Signature-256`: GitHub webhook signature (required)
- `X-GitHub-Event`: Event type, must be "pull_request" (required)
- `Content-Type`: application/json (required)

**Response:**
```json
{
  "status": "success|ignored|error",
  "message": "Description of result",
  "review_id": "unique-review-identifier",
  "conversation_id": "openhands-conversation-id"
}
```

**Status Codes:**
- `200`: Request processed (check status field for result)
- `400`: Invalid request (malformed JSON, etc.)
- `401`: Invalid signature
- `500`: Server error

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

## Security Considerations

### Webhook Signature Validation

All incoming webhooks are validated using HMAC-SHA256 signatures to ensure:
- Requests originate from GitHub
- Payload hasn't been tampered with
- Unauthorized access is prevented

### Repository Allowlist

Only repositories explicitly listed in `WEBHOOK_ALLOWED_REPOS` are processed:
- Prevents unauthorized usage
- Controls resource consumption
- Maintains security boundaries

### Token Security

- Use tokens with minimal required permissions
- Regularly rotate GitHub tokens
- Store tokens securely in environment variables
- Monitor token usage and access logs

## Troubleshooting

### Common Issues

#### Webhook Not Triggering
- Verify repository is in `WEBHOOK_ALLOWED_REPOS`
- Check webhook URL accessibility
- Confirm webhook secret matches `WEBHOOK_SECRET`
- Review GitHub webhook delivery logs

#### Authentication Errors
- Validate `GITHUB_TOKEN` is current and has required permissions
- Check token expiration date
- Verify token scope includes necessary permissions

#### Review Not Generated
- Check OpenHands logs for conversation creation errors
- Verify AI model configuration
- Ensure sufficient API quota/credits

### Debug Steps

1. **Check Health Endpoint**
   ```bash
   curl https://your-openhands-instance.com/api/webhook/health
   ```

2. **Test Webhook Manually**
   ```bash
   python examples/webhook_test.py --url https://your-instance.com --repo your/repo
   ```

3. **Monitor Logs**
   ```bash
   # Look for these log messages:
   # "Processing PR review for {repo}#{pr_number}"
   # "PR review conversation created: {conversation_id}"
   # "Repository not allowed: {repo}"
   # "Invalid webhook signature"
   ```

4. **Verify Configuration**
   ```bash
   # Check environment variables are set
   echo $WEBHOOK_SECRET
   echo $WEBHOOK_ALLOWED_REPOS
   echo $GITHUB_TOKEN
   ```

### Error Messages

| Message | Cause | Solution |
|---------|-------|----------|
| "Invalid signature" | Webhook secret mismatch | Verify `WEBHOOK_SECRET` matches GitHub webhook configuration |
| "Repository not in allowed list" | Repository not configured | Add repository to `WEBHOOK_ALLOWED_REPOS` |
| "GITHUB_TOKEN environment variable not set" | Missing token | Set `GITHUB_TOKEN` environment variable |
| "Webhook secret not configured" | Missing secret | Set `WEBHOOK_SECRET` environment variable |

## Testing

### Unit Tests

Run the webhook unit tests:

```bash
poetry run pytest tests/unit/test_webhook.py -v
```

### Integration Tests

Run integration tests (requires test environment):

```bash
poetry run pytest tests/integration/test_webhook_integration.py -v
```

### Manual Testing

Use the provided test script for end-to-end testing:

```bash
python examples/webhook_test.py \
  --url http://localhost:8000 \
  --repo test/repo \
  --secret test-secret
```

## Future Enhancements

### Planned Features
- **Multi-Provider Support**: GitLab and Bitbucket webhook integration
- **Automatic Fix PRs**: Generate and submit fix PRs for identified issues
- **Custom Review Rules**: Repository-specific review configurations
- **Review Templates**: Customizable review comment templates
- **Metrics Dashboard**: Review statistics and performance analytics
- **Batch Processing**: Handle multiple PRs efficiently
- **Review Scheduling**: Delayed or scheduled reviews

### Extension Points
- Custom review criteria based on file types
- Integration with CI/CD pipelines
- Slack/Teams notifications for reviews
- Custom webhook event handlers
- Review result caching and optimization

## Contributing

### Adding New Features

1. Follow the existing code structure in `openhands/server/routes/webhook.py`
2. Add comprehensive tests in `tests/unit/test_webhook.py`
3. Update documentation in this file
4. Ensure pre-commit hooks pass

### Code Style

- Follow existing Python conventions
- Use type hints for all functions
- Add comprehensive docstrings
- Include error handling and logging

### Testing Requirements

- Unit tests for all new functionality
- Integration tests for end-to-end workflows
- Manual testing with real GitHub webhooks
- Performance testing for high-volume scenarios

## Support

For issues and questions:

1. Check the troubleshooting section above
2. Review OpenHands logs for error details
3. Test with the provided example scripts
4. Open an issue with detailed reproduction steps

## License

This webhook system is part of OpenHands and follows the same licensing terms.