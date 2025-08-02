"""GitHub webhook handler for automated PR reviews."""

import hashlib
import hmac
import json
import os
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from openhands.core.logger import openhands_logger as logger
from openhands.server.dependencies import get_dependencies
from openhands.server.services.pr_reviewer import PRReviewerService
from openhands.server.user_auth import get_user_settings
from openhands.storage.data_models.settings import Settings

app = APIRouter(prefix='/api/webhook', tags=['webhook'], dependencies=get_dependencies())


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


def is_repository_allowed(repo_full_name: str, allowed_repos: str | None) -> bool:
    """Check if repository is in the allowed list."""
    if not allowed_repos or allowed_repos.strip() == '':
        return True  # Allow all repositories if no restriction is set

    allowed_list = [repo.strip() for repo in allowed_repos.split(',')]
    return repo_full_name in allowed_list


@app.post('/github')
async def handle_github_webhook(
    request: Request, settings: Settings = Depends(get_user_settings)
):
    """Handle GitHub webhook events for PR reviews."""
    try:
        # Get webhook secret from settings
        webhook_secret = settings.webhook_secret.get_secret_value() if settings.webhook_secret else None
        if not webhook_secret:
            logger.warning('Webhook secret not configured, rejecting webhook')
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
        if not is_repository_allowed(repo_full_name, settings.webhook_allowed_repos):
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
            repo_full_name=repo_full_name, 
            pr_number=pr_number, 
            action=action,
            auto_fix=settings.webhook_auto_fix
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
async def webhook_health(settings: Settings = Depends(get_user_settings)):
    """Health check endpoint for webhook service."""
    return {
        'status': 'healthy',
        'webhook_secret_configured': bool(settings.webhook_secret),
        'allowed_repos_configured': bool(settings.webhook_allowed_repos),
        'auto_fix_enabled': settings.webhook_auto_fix,
    }
