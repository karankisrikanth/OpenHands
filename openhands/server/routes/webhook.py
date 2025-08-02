"""GitHub webhook handler for automated PR reviews."""

import hashlib
import hmac
import json
import os
from typing import Any

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel

from openhands.core.logger import openhands_logger as logger
from openhands.server.services.pr_reviewer import PRReviewerService

app = APIRouter(prefix='/api/webhook', tags=['webhook'])


class WebhookPayload(BaseModel):
    """GitHub webhook payload model."""

    action: str
    number: int | None = None
    pull_request: dict[str, Any] | None = None
    repository: dict[str, Any] | None = None
    sender: dict[str, Any] | None = None


def verify_webhook_signature(
    payload_body: bytes, signature_header: str, secret: str
) -> bool:
    """Verify GitHub webhook signature using HMAC-SHA256."""
    if not signature_header.startswith('sha256='):
        return False

    expected_signature = hmac.new(
        secret.encode('utf-8'), payload_body, hashlib.sha256
    ).hexdigest()

    received_signature = signature_header[7:]  # Remove 'sha256=' prefix

    return hmac.compare_digest(expected_signature, received_signature)


def is_repository_allowed(repo_full_name: str) -> bool:
    """Check if repository is in the allowed list."""
    allowed_repos = os.getenv('WEBHOOK_ALLOWED_REPOS', '')
    if not allowed_repos:
        return False

    allowed_list = [repo.strip() for repo in allowed_repos.split(',')]
    return repo_full_name in allowed_list


@app.post('/github')
async def handle_github_webhook(request: Request):
    """Handle GitHub webhook events for PR reviews."""
    try:
        # Get webhook secret from environment
        webhook_secret = os.getenv('WEBHOOK_SECRET')
        if not webhook_secret:
            logger.warning('WEBHOOK_SECRET not configured, rejecting webhook')
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail='Webhook secret not configured',
            )

        # Get request body and signature
        payload_body = await request.body()
        signature_header = request.headers.get('X-Hub-Signature-256', '')

        # Verify webhook signature
        if not verify_webhook_signature(payload_body, signature_header, webhook_secret):
            logger.warning('Invalid webhook signature')
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid signature'
            )

        # Parse payload
        try:
            payload = json.loads(payload_body.decode('utf-8'))
        except json.JSONDecodeError:
            logger.error('Invalid JSON payload')
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail='Invalid JSON payload'
            )

        # Extract event type
        event_type = request.headers.get('X-GitHub-Event', '')

        # Only handle pull request events
        if event_type != 'pull_request':
            logger.info(f'Ignoring non-PR event: {event_type}')
            return {'status': 'ignored', 'reason': 'not a pull request event'}

        # Extract repository information
        repository = payload.get('repository', {})
        repo_full_name = repository.get('full_name', '')

        # Check if repository is allowed
        if not is_repository_allowed(repo_full_name):
            logger.info(f'Repository not allowed: {repo_full_name}')
            return {'status': 'ignored', 'reason': 'repository not in allowed list'}

        # Extract PR information
        action = payload.get('action', '')
        pull_request = payload.get('pull_request', {})

        # Only handle opened and synchronize (updated) PRs
        if action not in ['opened', 'synchronize']:
            logger.info(f'Ignoring PR action: {action}')
            return {'status': 'ignored', 'reason': f'action {action} not handled'}

        # Extract PR details
        pr_number = pull_request.get('number')
        pr_title = pull_request.get('title', '')
        pr_author = pull_request.get('user', {}).get('login', '')

        logger.info(
            f'Processing PR review for {repo_full_name}#{pr_number}: {pr_title}',
            extra={
                'repo': repo_full_name,
                'pr_number': pr_number,
                'action': action,
                'author': pr_author,
            },
        )

        # Initialize PR reviewer service
        pr_reviewer = PRReviewerService()

        # Start PR review process
        review_result = await pr_reviewer.review_pull_request(
            repo_full_name=repo_full_name, pr_number=pr_number, action=action
        )

        return {
            'status': 'success',
            'message': 'PR review initiated',
            'review_id': review_result.get('review_id'),
            'conversation_id': review_result.get('conversation_id'),
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f'Webhook processing error: {str(e)}', exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Internal server error',
        )


@app.get('/health')
async def webhook_health():
    """Health check endpoint for webhook service."""
    return {
        'status': 'healthy',
        'webhook_secret_configured': bool(os.getenv('WEBHOOK_SECRET')),
        'allowed_repos_configured': bool(os.getenv('WEBHOOK_ALLOWED_REPOS')),
        'auto_fix_enabled': os.getenv('WEBHOOK_AUTO_FIX', 'false').lower() == 'true',
    }
