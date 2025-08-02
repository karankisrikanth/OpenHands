"""PR Reviewer Service for automated code review using OpenHands."""

import os
import uuid
from typing import Any

from pydantic import SecretStr

from openhands.core.logger import openhands_logger as logger
from openhands.integrations.github.github_service import GitHubService
from openhands.integrations.service_types import ProviderType
from openhands.server.services.conversation_service import create_new_conversation
from openhands.storage.data_models.conversation_metadata import ConversationTrigger


class PRReviewerService:
    """Service for automated PR reviews using OpenHands AI."""

    def __init__(self):
        self.github_service = None

    async def _get_github_service(self) -> GitHubService:
        """Get GitHub service instance with authentication."""
        if self.github_service is None:
            # Get GitHub token from environment
            github_token = os.getenv('GITHUB_TOKEN')
            if not github_token:
                raise ValueError('GITHUB_TOKEN environment variable not set')

            self.github_service = GitHubService(token=SecretStr(github_token))

        return self.github_service

    async def review_pull_request(
        self, repo_full_name: str, pr_number: int, action: str, auto_fix: bool = False
    ) -> dict[str, Any]:
        """Review a pull request and post comments."""
        try:
            logger.info(f'Starting PR review for {repo_full_name}#{pr_number}')

            # Get GitHub service
            github_service = await self._get_github_service()

            # Fetch PR details and diff
            pr_data = await self._fetch_pr_data(
                github_service, repo_full_name, pr_number
            )
            pr_diff = await self._fetch_pr_diff(
                github_service, repo_full_name, pr_number
            )

            # Create conversation for PR review
            conversation_id = str(uuid.uuid4())

            # Prepare review message
            review_message = self._prepare_review_message(
                repo_full_name, pr_number, pr_data, pr_diff, action
            )

            # Create new conversation with PR review context
            await create_new_conversation(
                user_id='webhook-pr-reviewer',
                git_provider_tokens=None,
                custom_secrets=None,
                selected_repository=repo_full_name,
                selected_branch=pr_data.get('head', {}).get('ref'),
                initial_user_msg=review_message,
                image_urls=None,
                replay_json=None,
                conversation_instructions=self._get_review_instructions(auto_fix),
                conversation_trigger=ConversationTrigger.WEBHOOK,
                attach_convo_id=True,
                git_provider=ProviderType.GITHUB,
                conversation_id=conversation_id,
            )

            logger.info(
                f'PR review conversation created: {conversation_id}',
                extra={
                    'repo': repo_full_name,
                    'pr_number': pr_number,
                    'conversation_id': conversation_id,
                },
            )

            return {
                'review_id': str(uuid.uuid4()),
                'conversation_id': conversation_id,
                'status': 'initiated',
            }

        except Exception as e:
            logger.error(
                f'Error reviewing PR {repo_full_name}#{pr_number}: {str(e)}',
                exc_info=True,
            )
            raise

    async def _fetch_pr_data(
        self, github_service: GitHubService, repo_full_name: str, pr_number: int
    ) -> dict[str, Any]:
        """Fetch PR metadata from GitHub API."""
        url = f'{github_service.BASE_URL}/repos/{repo_full_name}/pulls/{pr_number}'
        response, _ = await github_service._make_request(url)
        return response

    async def _fetch_pr_diff(
        self, github_service: GitHubService, repo_full_name: str, pr_number: int
    ) -> str:
        """Fetch PR diff from GitHub API."""
        try:
            import httpx

            headers = await github_service._get_github_headers()
            headers['Accept'] = 'application/vnd.github.v3.diff'

            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f'{github_service.BASE_URL}/repos/{repo_full_name}/pulls/{pr_number}',
                    headers=headers,
                )
                response.raise_for_status()
                return response.text

        except Exception as e:
            logger.error(f'Error fetching PR diff: {str(e)}')
            return 'Error: Could not fetch PR diff'

    def _prepare_review_message(
        self,
        repo_full_name: str,
        pr_number: int,
        pr_data: dict[str, Any],
        pr_diff: str,
        action: str,
    ) -> str:
        """Prepare the initial message for PR review conversation."""
        pr_title = pr_data.get('title', 'Unknown')
        pr_author = pr_data.get('user', {}).get('login', 'Unknown')
        pr_url = pr_data.get('html_url', '')
        pr_description = pr_data.get('body', '') or 'No description provided'

        # Truncate diff if too long (GitHub API limit considerations)
        max_diff_length = 50000  # Reasonable limit for LLM context
        if len(pr_diff) > max_diff_length:
            pr_diff = (
                pr_diff[:max_diff_length] + '\n\n... (diff truncated due to length)'
            )

        message = f"""/codereview

Please review this pull request for code quality, security, and best practices.

**Repository:** {repo_full_name}
**PR #{pr_number}:** {pr_title}
**Author:** {pr_author}
**URL:** {pr_url}
**Action:** {action}

**Description:**
{pr_description}

**Code Changes:**
```diff
{pr_diff}
```

Please analyze the code changes and provide structured feedback following the code review guidelines. Focus on:

1. **Style and Formatting** - Check for consistency, unused imports, naming conventions
2. **Clarity and Readability** - Identify complex logic, poor naming, missing documentation
3. **Security and Bug Patterns** - Look for security vulnerabilities, common pitfalls

For each issue found, provide:
- Line number or range
- Brief explanation of the issue
- Concrete improvement suggestion

Use the format: [Line X] :emoji: Category: Description and suggestion.

After the review, if significant issues are found and auto-fix is enabled, you may also suggest specific code improvements."""

        return message

    def _get_review_instructions(self, auto_fix: bool = False) -> str:
        """Get conversation instructions for PR review."""
        instructions = """You are conducting an automated code review for a GitHub pull request.

Your role is to:
1. Analyze the provided code changes thoroughly
2. Identify issues related to code quality, security, and best practices
3. Provide constructive feedback with specific line references
4. Suggest concrete improvements

Guidelines:
- Be thorough but constructive in your feedback
- Focus on actionable improvements
- Use the structured format specified in the code review microagent
- Consider the context of the entire codebase when possible
- Prioritize security and correctness issues over style preferences"""

        if auto_fix:
            instructions += """
- If you find significant issues, you may suggest specific code fixes
- Provide clear explanations for any suggested changes"""

        return instructions

    async def post_review_comment(
        self, repo_full_name: str, pr_number: int, review_content: str
    ) -> bool:
        """Post review comment to GitHub PR."""
        try:
            github_service = await self._get_github_service()

            # Create review comment
            url = f'{github_service.BASE_URL}/repos/{repo_full_name}/pulls/{pr_number}/reviews'

            review_data = {
                'body': review_content,
                'event': 'COMMENT',  # Can be 'APPROVE', 'REQUEST_CHANGES', or 'COMMENT'
            }

            import httpx

            headers = await github_service._get_github_headers()
            headers['Content-Type'] = 'application/json'

            async with httpx.AsyncClient() as client:
                response = await client.post(url, headers=headers, json=review_data)
                response.raise_for_status()
                response_data = response.json()

            logger.info(
                f'Posted review comment to {repo_full_name}#{pr_number}',
                extra={
                    'repo': repo_full_name,
                    'pr_number': pr_number,
                    'review_id': response_data.get('id'),
                },
            )

            return True

        except Exception as e:
            logger.error(
                f'Error posting review comment to {repo_full_name}#{pr_number}: {str(e)}',
                exc_info=True,
            )
            return False
