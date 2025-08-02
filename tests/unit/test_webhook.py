"""Tests for GitHub webhook functionality."""

import hashlib
import hmac
import json
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from openhands.server.app import app
from openhands.server.routes.webhook import (
    is_repository_allowed,
    verify_webhook_signature,
)


class TestWebhookSignatureVerification:
    """Test webhook signature verification."""

    def test_verify_webhook_signature_valid(self):
        """Test valid webhook signature verification."""
        secret = 'test-secret'
        payload = b'{"test": "data"}'

        # Generate valid signature
        signature = hmac.new(
            secret.encode('utf-8'), payload, hashlib.sha256
        ).hexdigest()
        signature_header = f'sha256={signature}'

        assert verify_webhook_signature(payload, signature_header, secret) is True

    def test_verify_webhook_signature_invalid(self):
        """Test invalid webhook signature verification."""
        secret = 'test-secret'
        payload = b'{"test": "data"}'
        signature_header = 'sha256=invalid-signature'

        assert verify_webhook_signature(payload, signature_header, secret) is False

    def test_verify_webhook_signature_wrong_format(self):
        """Test webhook signature with wrong format."""
        secret = 'test-secret'
        payload = b'{"test": "data"}'
        signature_header = 'invalid-format'

        assert verify_webhook_signature(payload, signature_header, secret) is False


class TestRepositoryAllowlist:
    """Test repository allowlist functionality."""

    def test_is_repository_allowed_empty_list(self):
        """Test repository check with empty allowlist."""
        with patch.dict(os.environ, {'WEBHOOK_ALLOWED_REPOS': ''}):
            assert is_repository_allowed('owner/repo') is False

    def test_is_repository_allowed_single_repo(self):
        """Test repository check with single allowed repo."""
        with patch.dict(os.environ, {'WEBHOOK_ALLOWED_REPOS': 'owner/repo'}):
            assert is_repository_allowed('owner/repo') is True
            assert is_repository_allowed('other/repo') is False

    def test_is_repository_allowed_multiple_repos(self):
        """Test repository check with multiple allowed repos."""
        allowed_repos = 'owner1/repo1,owner2/repo2,owner3/repo3'
        with patch.dict(os.environ, {'WEBHOOK_ALLOWED_REPOS': allowed_repos}):
            assert is_repository_allowed('owner1/repo1') is True
            assert is_repository_allowed('owner2/repo2') is True
            assert is_repository_allowed('owner3/repo3') is True
            assert is_repository_allowed('other/repo') is False

    def test_is_repository_allowed_with_spaces(self):
        """Test repository check with spaces in configuration."""
        allowed_repos = 'owner1/repo1, owner2/repo2 , owner3/repo3'
        with patch.dict(os.environ, {'WEBHOOK_ALLOWED_REPOS': allowed_repos}):
            assert is_repository_allowed('owner1/repo1') is True
            assert is_repository_allowed('owner2/repo2') is True
            assert is_repository_allowed('owner3/repo3') is True


class TestWebhookEndpoints:
    """Test webhook HTTP endpoints."""

    def setup_method(self):
        """Set up test client."""
        self.client = TestClient(app)

    def test_webhook_health_endpoint(self):
        """Test webhook health check endpoint."""
        response = self.client.get('/api/webhook/health')
        assert response.status_code == 200

        data = response.json()
        assert 'status' in data
        assert 'webhook_secret_configured' in data
        assert 'allowed_repos_configured' in data
        assert 'auto_fix_enabled' in data

    @patch.dict(
        os.environ,
        {'WEBHOOK_SECRET': 'test-secret', 'WEBHOOK_ALLOWED_REPOS': 'test/repo'},
    )
    @patch('openhands.server.routes.webhook.PRReviewerService')
    def test_github_webhook_valid_pr_opened(self, mock_pr_reviewer):
        """Test valid GitHub webhook for PR opened event."""
        # Mock PR reviewer service
        mock_service = AsyncMock()
        mock_service.review_pull_request.return_value = {
            'review_id': 'test-review-id',
            'conversation_id': 'test-conversation-id',
        }
        mock_pr_reviewer.return_value = mock_service

        # Prepare webhook payload
        payload = {
            'action': 'opened',
            'number': 123,
            'pull_request': {
                'number': 123,
                'title': 'Test PR',
                'user': {'login': 'testuser'},
            },
            'repository': {'full_name': 'test/repo'},
        }

        payload_bytes = json.dumps(payload).encode('utf-8')
        signature = hmac.new(b'test-secret', payload_bytes, hashlib.sha256).hexdigest()

        # Make request
        response = self.client.post(
            '/api/webhook/github',
            content=payload_bytes,
            headers={
                'X-Hub-Signature-256': f'sha256={signature}',
                'X-GitHub-Event': 'pull_request',
                'Content-Type': 'application/json',
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data['status'] == 'success'
        assert data['message'] == 'PR review initiated'
        assert 'review_id' in data
        assert 'conversation_id' in data

    def test_github_webhook_missing_secret(self):
        """Test GitHub webhook without configured secret."""
        with patch.dict(os.environ, {}, clear=True):
            payload = {'action': 'opened'}
            payload_bytes = json.dumps(payload).encode('utf-8')

            response = self.client.post(
                '/api/webhook/github',
                content=payload_bytes,
                headers={
                    'X-Hub-Signature-256': 'sha256=invalid',
                    'X-GitHub-Event': 'pull_request',
                },
            )

            assert response.status_code == 500

    @patch.dict(os.environ, {'WEBHOOK_SECRET': 'test-secret'})
    def test_github_webhook_invalid_signature(self):
        """Test GitHub webhook with invalid signature."""
        payload = {'action': 'opened'}
        payload_bytes = json.dumps(payload).encode('utf-8')

        response = self.client.post(
            '/api/webhook/github',
            content=payload_bytes,
            headers={
                'X-Hub-Signature-256': 'sha256=invalid-signature',
                'X-GitHub-Event': 'pull_request',
            },
        )

        assert response.status_code == 401

    @patch.dict(
        os.environ,
        {'WEBHOOK_SECRET': 'test-secret', 'WEBHOOK_ALLOWED_REPOS': 'allowed/repo'},
    )
    def test_github_webhook_repository_not_allowed(self):
        """Test GitHub webhook for repository not in allowlist."""
        payload = {'action': 'opened', 'repository': {'full_name': 'not-allowed/repo'}}
        payload_bytes = json.dumps(payload).encode('utf-8')
        signature = hmac.new(b'test-secret', payload_bytes, hashlib.sha256).hexdigest()

        response = self.client.post(
            '/api/webhook/github',
            content=payload_bytes,
            headers={
                'X-Hub-Signature-256': f'sha256={signature}',
                'X-GitHub-Event': 'pull_request',
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data['status'] == 'ignored'
        assert 'not in allowed list' in data['reason']

    @patch.dict(
        os.environ,
        {'WEBHOOK_SECRET': 'test-secret', 'WEBHOOK_ALLOWED_REPOS': 'test/repo'},
    )
    def test_github_webhook_non_pr_event(self):
        """Test GitHub webhook for non-PR event."""
        payload = {'action': 'opened'}
        payload_bytes = json.dumps(payload).encode('utf-8')
        signature = hmac.new(b'test-secret', payload_bytes, hashlib.sha256).hexdigest()

        response = self.client.post(
            '/api/webhook/github',
            content=payload_bytes,
            headers={
                'X-Hub-Signature-256': f'sha256={signature}',
                'X-GitHub-Event': 'push',  # Not a PR event
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data['status'] == 'ignored'
        assert 'not a pull request event' in data['reason']

    @patch.dict(
        os.environ,
        {'WEBHOOK_SECRET': 'test-secret', 'WEBHOOK_ALLOWED_REPOS': 'test/repo'},
    )
    def test_github_webhook_ignored_pr_action(self):
        """Test GitHub webhook for ignored PR action."""
        payload = {
            'action': 'closed',  # Not handled action
            'repository': {'full_name': 'test/repo'},
        }
        payload_bytes = json.dumps(payload).encode('utf-8')
        signature = hmac.new(b'test-secret', payload_bytes, hashlib.sha256).hexdigest()

        response = self.client.post(
            '/api/webhook/github',
            content=payload_bytes,
            headers={
                'X-Hub-Signature-256': f'sha256={signature}',
                'X-GitHub-Event': 'pull_request',
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data['status'] == 'ignored'
        assert 'action closed not handled' in data['reason']


@pytest.mark.asyncio
class TestPRReviewerService:
    """Test PR reviewer service functionality."""

    @patch('openhands.server.services.pr_reviewer.create_new_conversation')
    @patch('openhands.server.services.pr_reviewer.GitHubService')
    @patch.dict(os.environ, {'GITHUB_TOKEN': 'test-token'})
    async def test_review_pull_request_success(
        self, mock_github_service, mock_create_conversation
    ):
        """Test successful PR review process."""
        from openhands.server.services.pr_reviewer import PRReviewerService

        # Mock GitHub service
        mock_service = AsyncMock()
        mock_service._make_request.return_value = (
            {
                'title': 'Test PR',
                'user': {'login': 'testuser'},
                'html_url': 'https://github.com/test/repo/pull/123',
                'body': 'Test description',
                'head': {'ref': 'feature-branch'},
            },
            {},
        )
        mock_github_service.return_value = mock_service

        # Mock diff fetch
        with patch('httpx.AsyncClient') as mock_client:
            mock_response = MagicMock()
            mock_response.text = 'diff content'
            mock_response.raise_for_status.return_value = None
            mock_client.return_value.__aenter__.return_value.get.return_value = (
                mock_response
            )

            # Mock conversation creation
            mock_create_conversation.return_value = MagicMock()

            # Test PR review
            reviewer = PRReviewerService()
            result = await reviewer.review_pull_request('test/repo', 123, 'opened')

            assert 'review_id' in result
            assert 'conversation_id' in result
            assert result['status'] == 'initiated'

    @patch.dict(os.environ, {}, clear=True)
    async def test_review_pull_request_missing_token(self):
        """Test PR review with missing GitHub token."""
        from openhands.server.services.pr_reviewer import PRReviewerService

        reviewer = PRReviewerService()

        with pytest.raises(
            ValueError, match='GITHUB_TOKEN environment variable not set'
        ):
            await reviewer.review_pull_request('test/repo', 123, 'opened')
