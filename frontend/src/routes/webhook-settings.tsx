import React from "react";
import { useTranslation } from "react-i18next";
import { useSaveSettings } from "#/hooks/mutation/use-save-settings";
import { useSettings } from "#/hooks/query/use-settings";
import { BrandButton } from "#/components/features/settings/brand-button";
import { SettingsSwitch } from "#/components/features/settings/settings-switch";
import { SettingsInput } from "#/components/features/settings/settings-input";
import { I18nKey } from "#/i18n/declaration";
import {
  displayErrorToast,
  displaySuccessToast,
} from "#/utils/custom-toast-handlers";
import { retrieveAxiosErrorMessage } from "#/utils/retrieve-axios-error-message";

function WebhookSettingsScreen() {
  const { t } = useTranslation();

  const { mutate: saveSettings, isPending } = useSaveSettings();
  const { data: settings, isLoading } = useSettings();

  const [webhookSecretHasChanged, setWebhookSecretHasChanged] =
    React.useState(false);
  const [allowedReposHasChanged, setAllowedReposHasChanged] =
    React.useState(false);
  const [autoFixHasChanged, setAutoFixHasChanged] = React.useState(false);

  const formAction = (formData: FormData) => {
    const webhookSecret = formData.get("webhook-secret-input")?.toString();
    const allowedRepos = formData.get("allowed-repos-input")?.toString();
    const autoFix = formData.get("auto-fix-switch")?.toString() === "on";

    saveSettings(
      {
        webhook_secret: webhookSecret || null,
        webhook_allowed_repos: allowedRepos || null,
        webhook_auto_fix: autoFix,
      },
      {
        onSuccess: () => {
          displaySuccessToast(t(I18nKey.SETTINGS$SAVED));
        },
        onError: (error) => {
          const errorMessage = retrieveAxiosErrorMessage(error);
          displayErrorToast(errorMessage || t(I18nKey.ERROR$GENERIC));
        },
        onSettled: () => {
          setWebhookSecretHasChanged(false);
          setAllowedReposHasChanged(false);
          setAutoFixHasChanged(false);
        },
      },
    );
  };

  const checkIfWebhookSecretHasChanged = (value: string) => {
    const currentSecret = settings?.webhook_secret_set ? "***" : "";
    setWebhookSecretHasChanged(value !== currentSecret);
  };

  const checkIfAllowedReposHasChanged = (value: string) => {
    const currentRepos = settings?.webhook_allowed_repos || "";
    setAllowedReposHasChanged(value !== currentRepos);
  };

  const checkIfAutoFixHasChanged = (checked: boolean) => {
    const currentAutoFix = !!settings?.webhook_auto_fix;
    setAutoFixHasChanged(checked !== currentAutoFix);
  };

  const formIsClean =
    !webhookSecretHasChanged && !allowedReposHasChanged && !autoFixHasChanged;

  const shouldBeLoading = !settings || isLoading || isPending;

  if (shouldBeLoading) {
    return (
      <div className="p-9 flex flex-col gap-6">
        <div className="animate-pulse">
          <div className="h-4 bg-gray-300 rounded w-1/4 mb-2"></div>
          <div className="h-10 bg-gray-300 rounded w-full"></div>
        </div>
        <div className="animate-pulse">
          <div className="h-4 bg-gray-300 rounded w-1/4 mb-2"></div>
          <div className="h-10 bg-gray-300 rounded w-full"></div>
        </div>
        <div className="animate-pulse">
          <div className="h-4 bg-gray-300 rounded w-1/4 mb-2"></div>
          <div className="h-6 bg-gray-300 rounded w-12"></div>
        </div>
      </div>
    );
  }

  return (
    <form
      data-testid="webhook-settings-screen"
      action={formAction}
      className="flex flex-col h-full justify-between"
    >
      <div className="p-9 flex flex-col gap-6">
        <div className="mb-4">
          <h2 className="text-lg font-semibold mb-2">GitHub Webhook Settings</h2>
          <p className="text-sm text-gray-600">
            Configure GitHub webhook integration for automated PR reviews.
          </p>
        </div>

        <SettingsInput
          testId="webhook-secret-input"
          name="webhook-secret-input"
          type="password"
          label="Webhook Secret"
          defaultValue={settings.webhook_secret_set ? "***" : ""}
          onChange={checkIfWebhookSecretHasChanged}
          placeholder="Enter your GitHub webhook secret"
          className="w-full max-w-[680px]"
          description="Secret used to verify webhook signatures from GitHub"
        />

        <SettingsInput
          testId="allowed-repos-input"
          name="allowed-repos-input"
          type="text"
          label="Allowed Repositories"
          defaultValue={settings.webhook_allowed_repos || ""}
          onChange={checkIfAllowedReposHasChanged}
          placeholder="owner/repo1,owner/repo2"
          className="w-full max-w-[680px]"
          description="Comma-separated list of repositories allowed to trigger reviews (e.g., owner/repo1,owner/repo2)"
        />

        <SettingsSwitch
          testId="auto-fix-switch"
          name="auto-fix-switch"
          defaultIsToggled={!!settings.webhook_auto_fix}
          onToggle={checkIfAutoFixHasChanged}
        >
          Enable Automatic Fix Generation
          <div className="text-sm text-gray-600 mt-1">
            When enabled, the AI will attempt to generate fixes for identified issues
          </div>
        </SettingsSwitch>

        <div className="mt-6 p-4 bg-blue-50 border border-blue-200 rounded-lg">
          <h3 className="text-sm font-semibold text-blue-800 mb-2">
            Setup Instructions
          </h3>
          <ol className="text-sm text-blue-700 space-y-1">
            <li>1. Go to your GitHub repository settings</li>
            <li>2. Navigate to Webhooks section</li>
            <li>3. Add webhook with URL: <code className="bg-blue-100 px-1 rounded">https://your-domain.com/api/webhook/github</code></li>
            <li>4. Set Content type to "application/json"</li>
            <li>5. Enter the webhook secret you configured above</li>
            <li>6. Select "Pull requests" events</li>
            <li>7. Ensure the repository is in your allowed list</li>
          </ol>
        </div>
      </div>

      <div className="flex gap-6 p-6 justify-end border-t border-t-tertiary">
        <BrandButton
          testId="submit-button"
          variant="primary"
          type="submit"
          isDisabled={isPending || formIsClean}
        >
          {!isPending && t("SETTINGS$SAVE_CHANGES")}
          {isPending && t("SETTINGS$SAVING")}
        </BrandButton>
      </div>
    </form>
  );
}

export default WebhookSettingsScreen;