# Github action for setting KUBECONFIG using vault

A custom Github Action that can be used to read environments from vault.

### Requires permissions:

The following [permissions](https://docs.github.com/en/actions/using-jobs/assigning-permissions-to-jobs#defining-access-for-the-github_token-scopes) need to be defined in [your GitHub Actions workflow](https://github.com/nrkno/plattform-github-apps/blob/6b6e96ab3824630f728574d0362687d1be96e7f4/.github/workflows/policy-bot.yaml#L28) in order to use this custom action.

```yaml
permissions:
  id-token: write
  contents: read
```

### Note:

## Example usage:

### Common issues

## Inputs

```yaml
inputs:
```

## Outputs

## Contributing

Create an issue and optionally a pull-request.
Use semantic commit messages.
