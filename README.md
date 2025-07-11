# Github action for setting KUBECONFIG using vault
A custom Github Action that can be used to create a kubernetes-config from vault kubernetes auth and secrets in vault. This custom action was created because the official hashicorp/vault action only supports `GET` requests, while the kubernetes auth method in vault requires `POST`.

### Requires permissions: ###
The following [permissions](https://docs.github.com/en/actions/using-jobs/assigning-permissions-to-jobs#defining-access-for-the-github_token-scopes) need to be defined in [your GitHub Actions workflow](https://github.com/nrkno/plattform-github-apps/blob/6b6e96ab3824630f728574d0362687d1be96e7f4/.github/workflows/policy-bot.yaml#L28) in order to use this custom action.

```yaml
permissions:
  id-token: write
  actions: read
  contents: read
```

### Note: ###
The kubeconfig file is stored in the GITHUB_WORKSPACE, same as where the checkout action stores the repo. Use `output-only: true` to not export KUBECONFIG file and env variable.
*By default the config will be valid for **10 minutes**. Use input vault-sa-ttl to change.*

## Example usage:
Example with deployment to kubernetes cluster.
Vault-role is `appname-environment`
```yaml
      - uses: nrkno/github-action-vault-to-k8s-config@v2.0
        id: vault-to-k8s-config
        with:
          vault-address: ${{ secrets.PLATTFORM_VAULT_URL }}
          vault-role: plattform-gorgon-api-github-prod
          cluster: aks-plattform-int-prod-eno
          namespace: gorgon-api-prod
      - uses: azure/k8s-deploy@v4.5
        with:
          manifests: prod/
          images: |
            plattform.azurecr.io/plattform/gorgon:latest
          annotate-namespace: false
          action: deploy
```

_You can find additional examples of usage by [searching for usages of the github-action-vault-to-k8s-config action in the nrkno organization on GitHub](https://github.com/search?q=org%3Anrkno+uses%3A+nrkno%2Fgithub-action-vault-to-k8s-config+language%3AYAML&type=code&l=YAML)._

### Common issues

#### Failed creating vault token
If github-action-vault-to-k8s-config [fails with the error "Failed creating vault token"](https://github.com/nrkno/valg-valgportal-2023-api/actions/runs/5517809972/job/14938542371), you've probably forgot to add the required permissions to your workflow, as described below.

## Inputs
```yaml
inputs:
  vault-address:
    description: 'address to your vault'
    required: true
  vault-role:
    description: 'Your github applications vault role'
    required: true
  vault-path:
    description: 'Auth path for vault'
    default: jwt-github
    required: false
  vault-sa-ttl:
    description: 'How long the service account for the kubeconfig will exist'
    default: 10m
    required: false
  cluster:
    description: 'The name of your kubernetes cluster'
    required: true
  namespace:
    description: 'The name of your kubernetes namespace'
    required: true
  cluster-rolebinding:
    description: 'Rolebinding to give ServiceAccount in the cluster'
    required: false
    default: edit
  output-only:
    description: "If true, KUBECONFIG env variable wont be set, and kubeconfig file won't be written to GITHUB_WORKSPACE"
    required: false
    default: "false"
```

## Outputs
```yaml
  k8s-config:
    description: 'The kube-config for your dynamic service account'
  ingress-suffix:
    description: 'Ingress suffix for the cluster'
```

## Contributing
Create an issue and optionally a pull-request.
Use semantic commit messages.