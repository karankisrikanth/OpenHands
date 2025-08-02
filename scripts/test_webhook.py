#!/usr/bin/env python3
"""
Test script for GitHub webhook PR review system.

This script demonstrates how to test the webhook system locally
without requiring actual GitHub webhook deliveries.
"""

import hashlib
import hmac
import json
import requests
import sys
from typing import Dict, Any


def create_webhook_signature(payload: Dict[str, Any], secret: str) -> str:
    """Create GitHub webhook signature for payload validation."""
    payload_bytes = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    signature = hmac.new(secret.encode(), payload_bytes, hashlib.sha256).hexdigest()
    return f'sha256={signature}'


def test_webhook_health(base_url: str) -> bool:
    """Test webhook health endpoint."""
    print("Testing webhook health endpoint...")
    
    try:
        response = requests.get(f"{base_url}/api/webhook/health")
        print(f"Health check status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"Response: {json.dumps(data, indent=2)}")
            return True
        else:
            print(f"Health check failed: {response.text}")
            return False
    except Exception as e:
        print(f"Health check error: {e}")
        return False


def test_webhook_pr_event(base_url: str, webhook_secret: str, repository: str) -> bool:
    """Test webhook with a simulated PR opened event."""
    print(f"\nTesting webhook with PR opened event for {repository}...")
    
    # Create a realistic PR payload
    payload = {
        "action": "opened",
        "number": 123,
        "pull_request": {
            "id": 123456789,
            "number": 123,
            "title": "Test PR for webhook review",
            "body": "This is a test pull request to verify webhook functionality.",
            "head": {
                "sha": "abc123def456",
                "ref": "feature/test-webhook",
                "repo": {
                    "full_name": repository,
                    "clone_url": f"https://github.com/{repository}.git"
                }
            },
            "base": {
                "sha": "def456abc123",
                "ref": "main",
                "repo": {
                    "full_name": repository,
                    "clone_url": f"https://github.com/{repository}.git"
                }
            },
            "diff_url": f"https://github.com/{repository}/pull/123.diff",
            "patch_url": f"https://github.com/{repository}/pull/123.patch",
            "_links": {
                "self": {"href": f"https://api.github.com/repos/{repository}/pulls/123"},
                "html": {"href": f"https://github.com/{repository}/pull/123"},
                "issue": {"href": f"https://api.github.com/repos/{repository}/issues/123"},
                "comments": {"href": f"https://api.github.com/repos/{repository}/issues/123/comments"},
                "review_comments": {"href": f"https://api.github.com/repos/{repository}/pulls/123/comments"},
                "review_comment": {"href": f"https://api.github.com/repos/{repository}/pulls/comments{{/number}}"},
                "commits": {"href": f"https://api.github.com/repos/{repository}/pulls/123/commits"},
                "statuses": {"href": f"https://api.github.com/repos/{repository}/statuses/abc123def456"}
            }
        },
        "repository": {
            "id": 987654321,
            "full_name": repository,
            "name": repository.split('/')[-1],
            "owner": {
                "login": repository.split('/')[0],
                "type": "User"
            },
            "clone_url": f"https://github.com/{repository}.git",
            "html_url": f"https://github.com/{repository}"
        },
        "sender": {
            "login": "test-user",
            "type": "User"
        }
    }
    
    # Create signature
    signature = create_webhook_signature(payload, webhook_secret)
    
    # Prepare headers
    headers = {
        'Content-Type': 'application/json',
        'X-GitHub-Event': 'pull_request',
        'X-Hub-Signature-256': signature,
        'User-Agent': 'GitHub-Hookshot/test'
    }
    
    try:
        response = requests.post(
            f"{base_url}/api/webhook/github",
            json=payload,
            headers=headers
        )
        
        print(f"Webhook response status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"Response: {json.dumps(data, indent=2)}")
            return True
        else:
            print(f"Webhook failed: {response.text}")
            return False
            
    except Exception as e:
        print(f"Webhook error: {e}")
        return False


def test_webhook_invalid_signature(base_url: str) -> bool:
    """Test webhook with invalid signature (should fail)."""
    print("\nTesting webhook with invalid signature...")
    
    payload = {"action": "opened", "test": "invalid_signature"}
    
    headers = {
        'Content-Type': 'application/json',
        'X-GitHub-Event': 'pull_request',
        'X-Hub-Signature-256': 'sha256=invalid_signature',
        'User-Agent': 'GitHub-Hookshot/test'
    }
    
    try:
        response = requests.post(
            f"{base_url}/api/webhook/github",
            json=payload,
            headers=headers
        )
        
        print(f"Invalid signature test status: {response.status_code}")
        
        if response.status_code == 401:
            print("✓ Invalid signature correctly rejected")
            return True
        else:
            print(f"✗ Expected 401, got {response.status_code}: {response.text}")
            return False
            
    except Exception as e:
        print(f"Invalid signature test error: {e}")
        return False


def test_webhook_non_pr_event(base_url: str, webhook_secret: str) -> bool:
    """Test webhook with non-PR event (should be ignored)."""
    print("\nTesting webhook with non-PR event...")
    
    payload = {"action": "opened", "ref": "refs/heads/main"}
    signature = create_webhook_signature(payload, webhook_secret)
    
    headers = {
        'Content-Type': 'application/json',
        'X-GitHub-Event': 'push',  # Not a PR event
        'X-Hub-Signature-256': signature,
        'User-Agent': 'GitHub-Hookshot/test'
    }
    
    try:
        response = requests.post(
            f"{base_url}/api/webhook/github",
            json=payload,
            headers=headers
        )
        
        print(f"Non-PR event test status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'ignored':
                print("✓ Non-PR event correctly ignored")
                return True
            else:
                print(f"✗ Expected ignored status, got: {data}")
                return False
        else:
            print(f"✗ Expected 200, got {response.status_code}: {response.text}")
            return False
            
    except Exception as e:
        print(f"Non-PR event test error: {e}")
        return False


def main():
    """Main test function."""
    if len(sys.argv) < 4:
        print("Usage: python test_webhook.py <base_url> <webhook_secret> <repository>")
        print("Example: python test_webhook.py http://localhost:3000 my-secret-123 myuser/myrepo")
        sys.exit(1)
    
    base_url = sys.argv[1].rstrip('/')
    webhook_secret = sys.argv[2]
    repository = sys.argv[3]
    
    print(f"Testing webhook system at {base_url}")
    print(f"Repository: {repository}")
    print("=" * 60)
    
    # Run tests
    tests = [
        ("Health Check", lambda: test_webhook_health(base_url)),
        ("Valid PR Event", lambda: test_webhook_pr_event(base_url, webhook_secret, repository)),
        ("Invalid Signature", lambda: test_webhook_invalid_signature(base_url)),
        ("Non-PR Event", lambda: test_webhook_non_pr_event(base_url, webhook_secret)),
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"Test {test_name} failed with exception: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    passed = 0
    for test_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{test_name:<20} {status}")
        if result:
            passed += 1
    
    print(f"\nPassed: {passed}/{len(results)} tests")
    
    if passed == len(results):
        print("🎉 All tests passed! Webhook system is working correctly.")
        sys.exit(0)
    else:
        print("❌ Some tests failed. Check the output above for details.")
        sys.exit(1)


if __name__ == "__main__":
    main()