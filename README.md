# Github action for setting KUBECONFIG using vault

A custom Github Action that can be used to read environments from vault.

<!-- autodoc start -->
## setenv
Set enviroment variables from Vault app_role_applications

autodoc:
  permissions:
    id-token: write

### Required Inputs

|Input name|Description|Type|Default|
|---|---|---|---|
|**name**|Vault app_role_applications name|string|`unknown`|
|**env**|Vault environment eg: prod|string|`unknown`|

### Optional Inputs

|Input name|Description|Type|Default|
|---|---|---|---|
|**token**|Vault token, defaults to /vault/secrets/token|string|`None`|
|**cluster**|Can be used multiple times, exported in KUBE_CONFIG_PATH: ~/.kube/atlantis/config|string|`None`|
|**azure**|Get Azure credentials, exported as ARM_CLIENT_ID and ARM_CLIENT_SECRET|string|`None`|
|**azure_tenant_id**|Azure tenant ID. Required if --azure is set|string|``|
|**azure_subscription_id**|Azure subscription ID. Subscription ID for which your state is stored. Required if --azure is set|string|``|
|**azure_resource_group**|Azure resource group name. Resource group for which your state is stored. Required if --azure is set|string|``|
|**azure_no_arm**|Do not export ARM_CLIENT_ID and ARM_CLIENT_SECRET, only TF_VAR_azure_client_id and TF_VAR_azure_client_secret|string|`None`|
|**gcp**|GCP project names, creates TF_VAR_gcp_project_name for use in "credentials" in google provider|string|`None`|
|**terraform_registry**|Get Terraform registry token, expects to be found in vault under "token" in secret/applications/{name}/{env}/terraform-registry|string|`None`|
|**wait_time**|Time to wait in seconds after Azure credentials have been validated, defaults to 60|string|`None`|
|**eval**|Export the variables to GITHUB_ENV and GITHUB_OUTPUT (in GitHub Actions) or print export statements (elsewhere)|string|`None`|
|**new_line**|Output as text separated by newline|string|`None`|
|**debug**|Print progress messages|string|`None`|
|**vault_role_id_name**|Name of the environment variable for Vault role ID, defaults to "TF_VAR_vault_role_id"|string|`None`|
|**vault_secret_id_name**|Name of the environment variable for Vault secret ID, defaults to "TF_VAR_vault_secret_id"|string|`None`|
|**vault_secret_id_cidr**|CIDR to use for Vault secret ID, defaults to the IP address from --myip-url with /32 (IPv4) or /128 (IPv6) suffix|string|`None`|
|**cache**|Cache/ use cached credentials|string|`None`|
|**cache_file**|Path and name to cache file, defaults to /tmp/{repo_name}_{workflow_name}.cache.json when running in atlantis, or /tmp/{current_workdir}.cache.json when running from shell|string|`None`|
|**secret**|Every key/value pair in vault applications "setenv" secret is added to env vars on hardcoded path secret/applications/{name}/{env}/setenv|string|`None`|
|**vault_secret**|Get secret from vault, spec path to secret, key in secret and name of environment variable to export. Can be used multiple times, e.g. --vault-secret secret/applications/myapp/prod:mykey:MY_VAR_NAME. using * as key, all keys in secret will be exported with the speced var_name as prefix, e.g.: --vault-secret secret/applications/myapp/prod:*:MY_PREFIX_ will export MY_PREFIX_key1, MY_PREFIX_key2 etc.|string|`None`|
|**myip_url**|URL to get current IP address, default is https://icanhazip.com|string|`None`|



### Simple example usage

```yaml
---
name: Example Workflow using this Action
on:
  pull_request:

jobs:
  example-job:
    name: Example Job
    steps:
      - uses: actions/checkout@v6
        with:
          ref: ${ github.head_ref }
          persist-credentials: true

      - name: example-step
        uses: nrkno/github-action-setenv@v3
        with:
          name: <value>
          env: <value>
          cache_file: <value>

      - name: Commit and push changes
        uses: stefanzweifel/git-auto-commit-action@v7
        with:
          commit_message: "docs(autodoc): update documentation"
```

### Full example usage

```yaml
---
name: Example Workflow using this Action
on:
  pull_request:

jobs:
  example-job:
    name: Example Job
    steps:
      - uses: actions/checkout@v6
        with:
          ref: ${ github.head_ref }
          persist-credentials: true

      - name: example-step
        uses: nrkno/github-action-setenv@v3
        with:
          name: <value>
          env: <value>
          cache_file: <value>
          token: <value> # Optional
          cluster: <value> # Optional
          azure: <value> # Optional
          azure_tenant_id:  # Optional
          azure_subscription_id:  # Optional
          azure_resource_group:  # Optional
          azure_no_arm: <value> # Optional
          gcp: <value> # Optional
          terraform_registry: <value> # Optional
          wait_time: <value> # Optional
          eval: <value> # Optional
          new_line: <value> # Optional
          debug: <value> # Optional
          vault_role_id_name: <value> # Optional
          vault_secret_id_name: <value> # Optional
          vault_secret_id_cidr: <value> # Optional
          cache: <value> # Optional
          secret: <value> # Optional
          vault_secret: <value> # Optional
          myip_url: <value> # Optional

      - name: Commit and push changes
        uses: stefanzweifel/git-auto-commit-action@v7
        with:
          commit_message: "docs(autodoc): update documentation"
```


<!-- autodoc end -->

## Security notes

- **How values reach the job.** With `eval: true` in GitHub Actions the action writes each variable to `$GITHUB_ENV` and `$GITHUB_OUTPUT` itself, using a random heredoc delimiter, and prints `::add-mask::` for every line of the value. It no longer prints shell code that is evaluated. Values containing `$(...)`, backticks, quotes or newlines are passed through unchanged and are never executed. Without `eval`, nothing is exported and nothing is printed except mask commands. Outside GitHub Actions the printed shell assignments are quoted with `shlex`, and names must be plain shell identifiers.
- **Variable names are checked, not allow-listed.** A name is refused (the action exits non-zero, no variable is written) if it is empty, contains `=`, CR, LF, NUL or `<<`, or matches the deny list below. Hyphens, dots and lowercase names are accepted. The deny list is case-sensitive except where noted.
  - Shell and loader: `BASH_*`, `ENV`, `PATH`, `IFS`, `SHELL`, `HOME`, `PS4`, `PROMPT_COMMAND`, `LD_*`, `DYLD_*`, `GCONV_PATH`, `LESSOPEN`, `LESSCLOSE`.
  - Language runtimes: `PYTHON*`, `NODE_OPTIONS`, `NODE_PATH`, `NODE_EXTRA_CA_CERTS`, `PERL5OPT`, `PERL5LIB`, `RUBYOPT`, `RUBYLIB`, `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`, `JDK_JAVA_OPTIONS`.
  - Tools: all `GIT_*` (including `GIT_CONFIG_*`), `TF_CLI_ARGS*`, `TF_CLI_CONFIG_FILE`, `TERRAFORM_CONFIG`, `TF_PLUGIN_CACHE_DIR`, `TF_DATA_DIR`, `KUBECONFIG`, `VAULT_ADDR`, `PIP_INDEX_URL`, `PIP_EXTRA_INDEX_URL`.
  - TLS and proxies: `SSL_CERT_FILE`, `SSL_CERT_DIR`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, and in any letter case `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`, `FTP_PROXY`, `NPM_CONFIG_*`.
  - Runner: `GITHUB_*`, `RUNNER_*`, `ACTIONS_*`.

  This is a deny list. It cannot know every variable that a later step or third-party tool treats as configuration, so a Vault writer can still set variables that are not listed. Treat write access to the `setenv` secret and `vault_secret` paths as access to the job's environment. An allow-list (for example `TF_VAR_*`, `ARM_*`, `TF_TOKEN_*`) would be stricter but breaks callers that export other names, so it has not been adopted.
- **Everything exported is visible to all later steps in the job.** Only use this action in jobs that do not run untrusted third-party code.
- **Image.** `action.yaml` uses `image: Dockerfile`, so the container is built from the action ref the workflow pins, and the code that runs always matches that ref. No image is published to GHCR any more; older `ghcr.io/nrkno/github-action-setenv` tags remain only for callers still pinned to old releases. The base image in `Dockerfile` is pinned by digest, and Renovate should keep it current. The first step of a job using this action takes longer because it builds the image.
- **Release job.** `release.yaml` installs the locked npm toolchain with `npm ci --ignore-scripts`. Its checkout keeps credentials because `semantic-release-tags` pushes tags with a plain `git push`. The job has `contents`, `issues` and `pull-requests` write only and no package permissions.
- **Azure.** With `azure: true`, tenant ID, subscription ID and resource group are all required, and the action fails if the credentials or resource group cannot be validated within about five minutes.
- **Tests.** `python3 -I -m unittest discover -s tests -v` runs the injection tests against a fake Vault.

## Lockfile upkeep

`.github/workflows/actions.lock` is generated by the
[`gh actions-lock`](https://github.com/github/gh-actions-lock) extension. Step
`uses:` references keep full version tags (`actions/checkout@v7.0.1`); the
lockfile records the commit SHA each tag resolved to, including transitive
actions, and GitHub enforces those SHAs when the workflow runs. A moved or
re-pointed tag therefore cannot change what runs. Whenever a `uses:` reference
in `.github/workflows/` is added, removed or changed, update the lockfile in the
same PR:

```sh
gh extension install github/gh-actions-lock --pin v0.4.1  # once
gh actions-lock
```

Commit `actions.lock` together with any tag rewrite the extension makes.
Renovate regenerates the lockfile in its action-bump PRs; run the command above for hand edits.

Reusable workflow calls (`jobs.<job_id>.uses`) are not covered by the lockfile.
Keep them pinned to a full commit SHA with a `# vX.Y.Z` comment.
The `Actions lockfile` workflow runs `gh actions-lock --verify-local` on PRs that
touch `.github/workflows/` and fails if an action reference has no lockfile
entry. Do not edit the lockfile by hand.

## Contributing

Create an issue and optionally a pull-request.
Use semantic commit messages.
