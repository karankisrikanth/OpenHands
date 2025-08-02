"""Integration tests for GitHub webhook functionality."""

import hashlib
import hmac
import json
import os
from unittest.mock import AsyncMock, patch

import pytest


@pytest.mark.asyncio
@pytest.mark.integration
class TestWebhookIntegration:
    """Integration tests for webhook functionality."""

    @pytest.fixture
    def webhook_payload(self):
        """Sample GitHub webhook payload for PR opened event."""
        return {
            'action': 'opened',
            'number': 123,
            'pull_request': {
                'id': 123456789,
                'number': 123,
                'title': 'Add new feature',
                'body': 'This PR adds a new feature to improve user experience.',
                'user': {'login': 'testuser', 'id': 12345},
                'head': {'ref': 'feature-branch', 'sha': 'abc123def456'},
                'base': {'ref': 'main', 'sha': 'def456abc123'},
                'html_url': 'https://github.com/test/repo/pull/123',
                'diff_url': 'https://github.com/test/repo/pull/123.diff',
                'mergeable': True,
                'state': 'open',
            },
            'repository': {
                'id': 987654321,
                'name': 'repo',
                'full_name': 'test/repo',
                'owner': {'login': 'test', 'id': 54321},
                'html_url': 'https://github.com/test/repo',
                'default_branch': 'main',
            },
            'sender': {'login': 'testuser', 'id': 12345},
        }

    @pytest.fixture
    def sample_diff(self):
        """Sample PR diff content."""
        return """diff --git a/src/main.py b/src/main.py
index 1234567..abcdefg 100644
--- a/src/main.py
+++ b/src/main.py
@@ -1,5 +1,10 @@
 import os
+import sys

 def main():
-    print("Hello World")
+    user_input = input("Enter your name: ")
+    print(f"Hello {user_input}")
+
+    # TODO: Add input validation
+    return 0

 if __name__ == "__main__":
     main()"""

    def create_webhook_signature(self, payload: dict, secret: str) -> str:
        """Create valid webhook signature for testing."""
        payload_bytes = json.dumps(payload, separators=(',', ':')).encode('utf-8')
        signature = hmac.new(
            secret.encode('utf-8'), payload_bytes, hashlib.sha256
        ).hexdigest()
        return f'sha256={signature}'

    @patch.dict(
        os.environ,
        {
            'WEBHOOK_SECRET': 'test-integration-secret',
            'WEBHOOK_ALLOWED_REPOS': 'test/repo',
            'GITHUB_TOKEN': 'test-token',
        },
    )
    @patch('openhands.server.services.pr_reviewer.create_new_conversation')
    @patch('httpx.AsyncClient')
    async def test_full_webhook_flow(
        self, mock_httpx, mock_create_conversation, webhook_payload, sample_diff
    ):
        """Test complete webhook flow from GitHub event to conversation creation."""
        # Mock GitHub API responses
        mock_client = AsyncMock()
        mock_httpx.return_value.__aenter__.return_value = mock_client

        # Mock PR details response
        pr_response = AsyncMock()
        pr_response.json.return_value = webhook_payload['pull_request']
        pr_response.raise_for_status.return_value = None
        mock_client.get.return_value = pr_response

        # Mock diff response
        diff_response = AsyncMock()
        diff_response.text = sample_diff
        diff_response.raise_for_status.return_value = None

        # Configure mock to return different responses based on headers
        def mock_get_side_effect(*args, **kwargs):
            headers = kwargs.get('headers', {})
            if headers.get('Accept') == 'application/vnd.github.v3.diff':
                return diff_response
            return pr_response

        mock_client.get.side_effect = mock_get_side_effect

        # Mock conversation creation
        mock_create_conversation.return_value = AsyncMock()

        # Test webhook endpoint
        from fastapi.testclient import TestClient

        from openhands.server.app import app

        client = TestClient(app)

        # Prepare request
        payload_bytes = json.dumps(webhook_payload, separators=(',', ':')).encode(
            'utf-8'
        )
        signature = self.create_webhook_signature(
            webhook_payload, 'test-integration-secret'
        )

        # Make webhook request
        response = client.post(
            '/api/webhook/github',
            content=payload_bytes,
            headers={
                'X-Hub-Signature-256': signature,
                'X-GitHub-Event': 'pull_request',
                'Content-Type': 'application/json',
            },
        )

        # Verify response
        assert response.status_code == 200
        data = response.json()
        assert data['status'] == 'success'
        assert data['message'] == 'PR review initiated'
        assert 'review_id' in data
        assert 'conversation_id' in data

        # Verify conversation was created with correct parameters
        mock_create_conversation.assert_called_once()
        call_args = mock_create_conversation.call_args

        # Check conversation parameters
        assert call_args.kwargs['user_id'] == 'webhook-pr-reviewer'
        assert call_args.kwargs['selected_repository'] == 'test/repo'
        assert call_args.kwargs['selected_branch'] == 'feature-branch'
        assert '/codereview' in call_args.kwargs['initial_user_msg']
        assert 'test/repo' in call_args.kwargs['initial_user_msg']
        assert 'Add new feature' in call_args.kwargs['initial_user_msg']
        assert sample_diff in call_args.kwargs['initial_user_msg']

    @patch.dict(
        os.environ,
        {'WEBHOOK_SECRET': 'test-secret', 'WEBHOOK_ALLOWED_REPOS': 'allowed/repo'},
    )
    async def test_webhook_repository_filtering(self, webhook_payload):
        """Test that webhook properly filters repositories."""
        from fastapi.testclient import TestClient

        from openhands.server.app import app

        client = TestClient(app)

        # Modify payload to use non-allowed repository
        webhook_payload['repository']['full_name'] = 'not-allowed/repo'

        payload_bytes = json.dumps(webhook_payload, separators=(',', ':')).encode(
            'utf-8'
        )
        signature = self.create_webhook_signature(webhook_payload, 'test-secret')

        response = client.post(
            '/api/webhook/github',
            content=payload_bytes,
            headers={
                'X-Hub-Signature-256': signature,
                'X-GitHub-Event': 'pull_request',
                'Content-Type': 'application/json',
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
    async def test_webhook_action_filtering(self, webhook_payload):
        """Test that webhook properly filters PR actions."""
        from fastapi.testclient import TestClient

        from openhands.server.app import app

        client = TestClient(app)

        # Test ignored action
        webhook_payload['action'] = 'closed'

        payload_bytes = json.dumps(webhook_payload, separators=(',', ':')).encode(
            'utf-8'
        )
        signature = self.create_webhook_signature(webhook_payload, 'test-secret')

        response = client.post(
            '/api/webhook/github',
            content=payload_bytes,
            headers={
                'X-Hub-Signature-256': signature,
                'X-GitHub-Event': 'pull_request',
                'Content-Type': 'application/json',
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data['status'] == 'ignored'
        assert 'action closed not handled' in data['reason']

    async def test_webhook_health_endpoint(self):
        """Test webhook health check endpoint."""
        from fastapi.testclient import TestClient

        from openhands.server.app import app

        client = TestClient(app)

        with patch.dict(
            os.environ,
            {
                'WEBHOOK_SECRET': 'test-secret',
                'WEBHOOK_ALLOWED_REPOS': 'test/repo',
                'WEBHOOK_AUTO_FIX': 'true',
            },
        ):
            response = client.get('/api/webhook/health')

            assert response.status_code == 200
            data = response.json()
            assert data['status'] == 'healthy'
            assert data['webhook_secret_configured'] is True
            assert data['allowed_repos_configured'] is True
            assert data['auto_fix_enabled'] is True

    @patch.dict(
        os.environ,
        {'WEBHOOK_SECRET': 'test-secret', 'WEBHOOK_ALLOWED_REPOS': 'test/repo'},
    )
    async def test_webhook_invalid_json(self):
        """Test webhook with invalid JSON payload."""
        from fastapi.testclient import TestClient

        from openhands.server.app import app

        client = TestClient(app)

        # Invalid JSON payload
        payload_bytes = b'{"invalid": json}'
        signature = hmac.new(b'test-secret', payload_bytes, hashlib.sha256).hexdigest()

        response = client.post(
            '/api/webhook/github',
            content=payload_bytes,
            headers={
                'X-Hub-Signature-256': f'sha256={signature}',
                'X-GitHub-Event': 'pull_request',
                'Content-Type': 'application/json',
            },
        )

        assert response.status_code == 400

    @patch.dict(
        os.environ,
        {'WEBHOOK_SECRET': 'test-secret', 'WEBHOOK_ALLOWED_REPOS': 'test/repo'},
    )
    async def test_webhook_non_pr_event(self, webhook_payload):
        """Test webhook with non-PR GitHub event."""
        from fastapi.testclient import TestClient

        from openhands.server.app import app

        client = TestClient(app)

        payload_bytes = json.dumps(webhook_payload, separators=(',', ':')).encode(
            'utf-8'
        )
        signature = self.create_webhook_signature(webhook_payload, 'test-secret')

        response = client.post(
            '/api/webhook/github',
            content=payload_bytes,
            headers={
                'X-Hub-Signature-256': signature,
                'X-GitHub-Event': 'push',  # Not a PR event
                'Content-Type': 'application/json',
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data['status'] == 'ignored'
        assert 'not a pull request event' in data['reason']
