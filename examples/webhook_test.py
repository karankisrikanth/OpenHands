#!/usr/bin/env python3
"""
Example script to test GitHub webhook functionality.

This script demonstrates how to:
1. Set up environment variables for webhook configuration
2. Send a test webhook payload to the OpenHands webhook endpoint
3. Verify the webhook response

Usage:
    python examples/webhook_test.py --url http://localhost:8000 --repo test/repo
"""

import argparse
import hashlib
import hmac
import json
import os
import sys
from typing import Any

import requests


def create_test_payload(repo_full_name: str, pr_number: int = 123) -> dict[str, Any]:
    """Create a test GitHub webhook payload for PR opened event."""
    return {
        'action': 'opened',
        'number': pr_number,
        'pull_request': {
            'id': 123456789,
            'number': pr_number,
            'title': 'Test PR for webhook validation',
            'body': 'This is a test PR to validate the webhook functionality.',
            'user': {'login': 'webhook-tester', 'id': 12345},
            'head': {'ref': 'feature/webhook-test', 'sha': 'abc123def456'},
            'base': {'ref': 'main', 'sha': 'def456abc123'},
            'html_url': f'https://github.com/{repo_full_name}/pull/{pr_number}',
            'diff_url': f'https://github.com/{repo_full_name}/pull/{pr_number}.diff',
            'mergeable': True,
            'state': 'open',
        },
        'repository': {
            'id': 987654321,
            'name': repo_full_name.split('/')[1],
            'full_name': repo_full_name,
            'owner': {'login': repo_full_name.split('/')[0], 'id': 54321},
            'html_url': f'https://github.com/{repo_full_name}',
            'default_branch': 'main',
        },
        'sender': {'login': 'webhook-tester', 'id': 12345},
    }


def create_webhook_signature(payload: dict[str, Any], secret: str) -> str:
    """Create HMAC-SHA256 signature for webhook payload."""
    payload_bytes = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    signature = hmac.new(
        secret.encode('utf-8'), payload_bytes, hashlib.sha256
    ).hexdigest()
    return f'sha256={signature}'


def test_webhook_health(base_url: str) -> bool:
    """Test webhook health endpoint."""
    try:
        response = requests.get(f'{base_url}/api/webhook/health', timeout=10)
        response.raise_for_status()

        data = response.json()
        print('✅ Webhook health check passed')
        print(f'   Status: {data.get("status")}')
        print(f'   Secret configured: {data.get("webhook_secret_configured")}')
        print(f'   Repos configured: {data.get("allowed_repos_configured")}')
        print(f'   Auto-fix enabled: {data.get("auto_fix_enabled")}')

        return data.get('status') == 'healthy'

    except requests.RequestException as e:
        print(f'❌ Webhook health check failed: {e}')
        return False


def test_webhook_endpoint(
    base_url: str, repo_full_name: str, webhook_secret: str
) -> bool:
    """Test webhook endpoint with sample payload."""
    try:
        # Create test payload
        payload = create_test_payload(repo_full_name)
        payload_bytes = json.dumps(payload, separators=(',', ':')).encode('utf-8')

        # Create signature
        signature = create_webhook_signature(payload, webhook_secret)

        # Prepare headers
        headers = {
            'X-Hub-Signature-256': signature,
            'X-GitHub-Event': 'pull_request',
            'Content-Type': 'application/json',
        }

        # Send webhook request
        response = requests.post(
            f'{base_url}/api/webhook/github',
            data=payload_bytes,
            headers=headers,
            timeout=30,
        )

        response.raise_for_status()
        data = response.json()

        print('✅ Webhook test passed')
        print(f'   Status: {data.get("status")}')
        print(f'   Message: {data.get("message")}')

        if data.get('status') == 'success':
            print(f'   Review ID: {data.get("review_id")}')
            print(f'   Conversation ID: {data.get("conversation_id")}')
        elif data.get('status') == 'ignored':
            print(f'   Reason: {data.get("reason")}')

        return True

    except requests.RequestException as e:
        print(f'❌ Webhook test failed: {e}')
        if hasattr(e, 'response') and e.response is not None:
            try:
                error_data = e.response.json()
                print(f'   Error details: {error_data}')
            except Exception:
                print(f'   Response text: {e.response.text}')
        return False


def main():
    """Main function to run webhook tests."""
    parser = argparse.ArgumentParser(description='Test GitHub webhook functionality')
    parser.add_argument('--url', required=True, help='Base URL of OpenHands instance')
    parser.add_argument('--repo', required=True, help='Repository name (owner/repo)')
    parser.add_argument(
        '--secret', help='Webhook secret (or set WEBHOOK_SECRET env var)'
    )
    parser.add_argument(
        '--pr-number', type=int, default=123, help='PR number for test payload'
    )

    args = parser.parse_args()

    # Get webhook secret
    webhook_secret = args.secret or os.getenv('WEBHOOK_SECRET')
    if not webhook_secret:
        print(
            '❌ Webhook secret not provided. Use --secret or set WEBHOOK_SECRET environment variable.'
        )
        sys.exit(1)

    print(f'🔧 Testing webhook functionality for {args.repo}')
    print(f'   OpenHands URL: {args.url}')
    print(f'   Repository: {args.repo}')
    print(f'   PR Number: {args.pr_number}')
    print()

    # Test health endpoint
    print('1. Testing webhook health endpoint...')
    health_ok = test_webhook_health(args.url)
    print()

    if not health_ok:
        print('❌ Health check failed. Please check your OpenHands configuration.')
        sys.exit(1)

    # Test webhook endpoint
    print('2. Testing webhook endpoint...')
    webhook_ok = test_webhook_endpoint(args.url, args.repo, webhook_secret)
    print()

    if webhook_ok:
        print('✅ All webhook tests passed!')
        print()
        print('Next steps:')
        print('1. Configure your GitHub repository webhook:')
        print(f'   - Payload URL: {args.url}/api/webhook/github')
        print('   - Content type: application/json')
        print('   - Secret: [your webhook secret]')
        print('   - Events: Pull requests')
        print('2. Create or update a pull request in your repository')
        print('3. Check OpenHands for the automated review conversation')
    else:
        print('❌ Webhook tests failed. Please check your configuration.')
        sys.exit(1)


if __name__ == '__main__':
    main()
