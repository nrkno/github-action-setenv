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

- **How values reach the job.** With `eval: true` in GitHub Actions the action writes each variable to `$GITHUB_ENV` and `$GITHUB_OUTPUT` itself, using a random heredoc delimiter, and prints `::add-mask::` for every line of the value. It no longer prints shell code that is evaluated. Values containing `$(...)`, backticks, quotes or newlines are passed through unchanged and are never executed. Without `eval`, nothing is exported and nothing is printed except mask commands.
- **Variable names are validated.** Names must match `^[A-Za-z_][A-Za-z0-9_]*$` and must not be `BASH_*`, `ENV`, `LD_*`, `DYLD_*`, `NODE_OPTIONS`, `NODE_PATH`, `PATH`, `PYTHON*`, `PS4`, `PROMPT_COMMAND`, `IFS`, `SHELL`, `HOME`, `GITHUB_*`, `RUNNER_*` or `ACTIONS_*`. A key such as `BASH_ENV` in the Vault `setenv` secret makes the action fail instead of exporting it.
- **Everything exported is visible to all later steps in the job.** Only use this action in jobs that do not run untrusted third-party code.
- **Image reference.** `action.yaml` references the image by release tag (`v3.2.1`), which is mutable. Digest pinning needs a commit made after the image is built, which would put the release tag on a commit that is not on `main`. That breaks semantic-release's version computation, so it is a deliberate follow-up: automate it without moving tags off `main`, or switch to a composite/Dockerfile action. The base image in `Dockerfile` is pinned by digest. Renovate should keep it current.
- **Tests.** `python3 -I -m unittest discover -s tests -v` runs the injection tests against a fake Vault.

## Contributing

Create an issue and optionally a pull-request.
Use semantic commit messages.
