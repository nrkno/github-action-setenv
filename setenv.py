#!/usr/bin/env python3
import json
import urllib.request
import os
import base64
import configargparse
import time
import sys
from datetime import datetime, timedelta

parser = configargparse.ArgParser(add_env_var_help=True, auto_env_var_prefix="INPUT_")
parser.add('--name', required=True, metavar="my-terraform-config", help='Vault app_role_applications name')
parser.add('--env', required=True, metavar="prod", help='Vault environment eg: prod')
parser.add('--cluster', action='append', metavar="cluster:role:namespace", default=[], help='Can be used multiple times, exported in KUBE_CONFIG_PATH: ~/.kube/atlantis/config')
parser.add('--azure', action='store_true', help='Get Azure credentials, exported as ARM_CLIENT_ID and ARM_CLIENT_SECRET')
parser.add('--azure-tenant-id', help='Azure tenant ID. Required if --azure is set')
parser.add('--azure-subscription-id', help='Azure subscription ID. Subscription ID for which your state is stored. Required if --azure is set')
parser.add('--azure-resource-group', help='Azure resource group name. Resource group for which your state is stored. Required if --azure is set')
parser.add('--azure-no-arm', action='store_true', help='Do not export ARM_CLIENT_ID and ARM_CLIENT_SECRET, only TF_VAR_azure_client_id and TF_VAR_azure_client_secret')
parser.add('--gcp', action='append', metavar="my-project", default=[], help='GCP project names, creates TF_VAR_gcp_project_name for use in "credentials" in google provider')
parser.add('--terraform-registry', action='store_true', help='Get Terraform registry token, expects to be found in vault under "token" in secret/applications/{name}/{env}/terraform-registry')
parser.add('--no-wait', action='store_true', help='Do not wait for credentials to propagate')
parser.add('--eval', action='store_true', help='Output as export statements, for use with eval $()')
parser.add('--new-line', action='store_true', help='Output as key=value separated by newline. If not set, output will be comma separated')
parser.add('--debug', action='store_true', help='Print progress messages')
parser.add('--token', help='Vault token, defaults to /vault/secrets/token')
parser.add('--vault-role-id-name', default='TF_VAR_vault_role_id', help='Name of the environment variable for Vault role ID, defaults to "TF_VAR_vault_role_id"')
parser.add('--vault-secret-id-name', default='TF_VAR_vault_secret_id', help='Name of the environment variable for Vault secret ID, defaults to "TF_VAR_vault_secret_id"')
parser.add('--vault-secret-id-cidr', default=None, help='CIDR to use for Vault secret ID, defaults to the IP address from --myip-url with /32 suffix')
parser.add('--cache', action='store_true', help='Cache/ use cached credentials')
parser.add('--cache-file', help='Path and name to cache file, defaults to /tmp/{repo_name}_{workflow_name}.cache.json when running in atlantis, or /tmp/{current_workdir}.cache.json when running from shell')
parser.add('--secret', action='store_true', help='Every key/value pair in vault applications "setenv" secret is added to env vars')
parser.add('--vault-secret', action='append',metavar="path:key:var_name", help='Get secret from vault, specify path to secret, key in secret and name of environment variable to export. Can be used multiple times, e.g. --vault-secret secret/applications/myapp/prod:mykey:MY_VAR_NAME. If using * as key, all keys in secret will be exported with the specified var_name as prefix, e.g.: --vault-secret secret/applications/myapp/prod:*:MY_PREFIX_ will export MY_PREFIX_key1, MY_PREFIX_key2 etc.')
parser.add('--myip-url', default='http://icanhazip.com', help='URL to get current IP address, default is http://icanhazip.com')
args = parser.parse_args()

vault_role = f"{args.name}-{args.env}"

def status(message, error=False):
    if args.debug or error:
        print(message, file=sys.stderr)

atlantis = False
github_actions = False
shell = False
cache_path = None

# This environment variable is set when running in Kubernetes or in Atlantis
if os.getenv('KUBERNETES_PORT'):
    # Get current IP
    status(f"Getting IP address from { args.myip_url} ...")
    response = urllib.request.urlopen(args.myip_url)
    reponse_ip = response.read().decode().strip()
    my_ip = f"{reponse_ip}/32"
    # Running in Kubernetes, use the token from the mounted secret
    atlantis = True
    args.token = open('/vault/secrets/token').read().strip()
    path_parts = os.getcwd().split("/")
    if not len(path_parts) >= 3:
        status("Could not generate cache filename, exiting...", True)
        sys.exit(0)
        
    # When running in atlantis, use repo and workflow name
    cache_path = f"/tmp/{path_parts[-3]}_{path_parts[-2]}.cache.json"

# This environment variable is set when running in GitHub Actions
elif os.getenv('GITHUB_ACTIONS'):
    # Get current IP
    status(f"Setting IP address from argument to { args.vault_secret_id_cidr } ...")
    my_ip = args.vault_secret_id_cidr
    # Running in GitHub Actions, use the token from the environment variable
    github_actions = True
    args.token = os.getenv('VAULT_TOKEN', args.token)
    if not args.token:
        status("Running in GitHub Actions, but no VAULT_TOKEN found", True)
        sys.exit(1)
    cache_path = f"/tmp/{os.getenv('GITHUB_REPOSITORY').replace('/', '_')}_{os.getenv('GITHUB_WORKFLOW').replace(" ", "_").lower()}.cache.json"

# If running from shell, check if token is provided
else:
    # Get current IP
    status(f"Getting IP address from { args.myip_url} ...")
    response = urllib.request.urlopen(args.myip_url)
    response_ip = response.read().decode().strip()
    my_ip = f"{response_ip}/32"
    # Running from shell, check if token is provided
    shell = True
    if not args.token:
        status("Running from shell, but no Vault token provided. Please specify with --token", True)
        sys.exit(1)

VAULT_ADDR = os.getenv('VAULT_ADDR', 'http://127.0.0.1:8200')
VAULT_TOKEN = args.token

def get_credentials_cache():
    """Get credentials from cache file"""
    if not args.cache:
        return None

    try:
        if not os.path.exists(cache_path):
            return None

        with open(cache_path, 'r') as f:
            cache_data = json.load(f)

        cache_time = datetime.fromisoformat(cache_data['timestamp'])
        if datetime.now() - cache_time < timedelta(minutes=45):
            status("Using cached credentials...")
            return cache_data['env_vars']
    except Exception as e:
        status(f"Error reading cache: {str(e)}", True)

    return None

def set_credentials_cache(env_vars=None):
    """Save credentials to cache file"""
    if not args.cache:
        return None

    if env_vars is not None:
        try:
            # Write file with restricted permissions (only owner can read/write)
            with open(cache_path, 'w') as f:
                os.chmod(cache_path, 0o600)  # Set permissions to 600
                json.dump({
                    'timestamp': datetime.now().isoformat(),
                    'env_vars': env_vars
                }, f)
            return None

        except Exception as e:
            status(f"Error saving cache: {str(e)}", True)
            return None
        
def output_env_vars(env_vars):
    """Output environment variables in the specified format"""
    if args.eval:
        if shell:
            status("Outputting environment variables for eval...")
            print(*[f"{'export ' if args.eval else ''}{k}='{v}'" for k, v in env_vars], sep='\n' if args.new_line else ' ')
        if github_actions:
            status("Outputting environment variables for GitHub Actions...")
            for k, v in env_vars:
                status(f"{k} is available as output")
                print(f'echo "::add-mask::{v}"')
                print(f'echo "{k}={v}" >> $GITHUB_OUTPUT')
                print(f'echo "{k}={v}" >> $GITHUB_ENV')
    else:
        status("Outputting environment variables...")
        print(*[f"{k}='{v}'" for k, v in env_vars], sep='\n' if args.new_line else ',')

    sys.exit(0)

cached_env_vars = get_credentials_cache()
if cached_env_vars:
    output_env_vars(cached_env_vars)
    sys.exit(0)

status(f"Using vault address: {VAULT_ADDR}", False)

vault_token = ""
def vault_request(path, method='GET', data=None):
    req = urllib.request.Request(
        f'{VAULT_ADDR}/v1/{path}',
        data=json.dumps(data).encode() if data else None,
        headers={
            'X-Vault-Token': vault_token,
            'Content-Type': 'application/json'
        },
        method=method
    )
    response = urllib.request.urlopen(req)
    return json.loads(response.read())

def _azure_get_token(tenant_id: str, client_id: str, client_secret: str) -> str:
    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    data = urllib.parse.urlencode(
        {
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": "https://management.azure.com/.default",
            "grant_type": "client_credentials",
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        token_url,
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        payload = json.load(resp)
    return payload["access_token"]

def azure_check_resource_group(tenant_id: str, subscription_id: str, resource_group: str, token: str) -> bool:
    url = (
        f"https://management.azure.com/subscriptions/{subscription_id}"
        f"/resourcegroups/{resource_group}?api-version=2021-04-01"
    )
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=10):
            return True
    except urllib.error.HTTPError as exc:
        if exc.code in (403, 404):
            return False
        raise

env_vars = []

# Log in using approle
try:
    status(f"Getting wrapped secret ID for role {vault_role}...")
    wrapped_token = json.loads(urllib.request.urlopen(urllib.request.Request(
        f'{VAULT_ADDR}/v1/auth/approle/role/{vault_role}/secret-id',
        data=json.dumps({"cidr_list": f"{my_ip}"}).encode(),
        headers={'Content-Type': 'application/json', 'X-Vault-Wrap-TTL': '5m', 'X-Vault-Request': 'true', 'X-Vault-Token': VAULT_TOKEN},
        method='PUT'
    )).read())['wrap_info']['token']

    status("Getting role ID...")
    role_id = json.loads(urllib.request.urlopen(urllib.request.Request(
        f'{VAULT_ADDR}/v1/auth/approle/role/{vault_role}/role-id',
        headers={'X-Vault-Request': 'true', 'X-Vault-Token': VAULT_TOKEN}
    )).read())['data']['role_id']
    env_vars.append((args.vault_role_id_name, role_id))

    status("Unwrapping secret ID...")
    secret_id = json.loads(urllib.request.urlopen(urllib.request.Request(
        f'{VAULT_ADDR}/v1/sys/wrapping/unwrap',
        data='null'.encode(),
        headers={'X-Vault-Request': 'true', 'X-Vault-Token': wrapped_token},
        method='PUT'
    )).read())['data']['secret_id']
    env_vars.append((args.vault_secret_id_name, secret_id))

    status("Logging in with AppRole...")
    login_req = urllib.request.Request(
        f'{VAULT_ADDR}/v1/auth/approle/login',
        data=json.dumps({"role_id": role_id, "secret_id": secret_id}).encode(),
        headers={'Content-Type': 'application/json'},
        method='POST'
    )
    login_response = urllib.request.urlopen(login_req)
    vault_token = json.loads(login_response.read())['auth']['client_token']

except urllib.error.HTTPError as e:
    status(f"HTTP Error: {e.code} - {e.reason}", True)
    status(f"Error response body: {e.read().decode()}", True)
    sys.exit(1)


if args.cluster:
    kubeconfig = {"apiVersion": "v1", "kind": "Config", "clusters": [], "contexts": [], "users": []}
    kubeconfig["current-context"] = args.cluster[0].split(':')[0]
    clusters = 0

    for cluster_str in args.cluster:
        if cluster_str == "None" or cluster_str == "":
            continue
        
        clusters += 1
        status(f"Getting Kubernetes credentials for {cluster_str}...")
        cluster, role, namespace = cluster_str.split(':')
        cluster_info = vault_request(f'secret/applications/shared/kubernetes-config/{cluster}')['data']
        creds = vault_request(
            f'kubernetes-{cluster}/creds/{vault_role}-{role}',
            method='PUT',
            data={'kubernetes_namespace': namespace}
        )['data']

        kubeconfig["clusters"].append({
            "name": cluster,
            "cluster": {
                "certificate-authority-data": base64.b64encode(cluster_info['ca_cert'].encode()).decode(),
                "server": cluster_info['host']
            }
        })
        kubeconfig["contexts"].append({
            "name": cluster,
            "context": {"cluster": cluster, "namespace": namespace, "user": f"{cluster}-{role}"}
        })
        kubeconfig["users"].append({
            "name": f"{cluster}-{role}",
            "user": {"token": creds['service_account_token']}
        })

    if clusters > 0:
      kubeconfig_path = os.path.expanduser('~/.kube/atlantis/config')
      os.makedirs(os.path.dirname(kubeconfig_path), exist_ok=True)
      with open(kubeconfig_path, 'w') as f:
          json.dump(kubeconfig, f, indent=2)
      env_vars.append(("KUBE_CONFIG_PATH", kubeconfig_path))

try:
    if args.azure:
        status("Getting Azure credentials...")
        azure_creds = vault_request(f'azure/creds/{vault_role}')['data']
        env_vars.extend([
            ("TF_VAR_azure_client_id", azure_creds['client_id']),
            ("TF_VAR_azure_client_secret", azure_creds['client_secret'])
        ])
        if not args.azure_no_arm:
            env_vars.extend([
                ("ARM_CLIENT_ID", azure_creds['client_id']),
                ("ARM_CLIENT_SECRET", azure_creds['client_secret'])
            ])
        
        tries=0
        status("Validating Azure credentials...")
        while True:
            token = _azure_get_token(
                tenant_id=args.azure_tenant_id,
                client_id=azure_creds['client_id'],
                client_secret=azure_creds['client_secret']
            )
            if azure_check_resource_group(
                tenant_id=args.azure_tenant_id,
                subscription_id=args.azure_subscription_id,
                resource_group=args.azure_resource_group,
                token=token
            ):
                status("Azure credentials are valid and resource group is accessible.")
                break
            else:
                status("Waiting for Azure credentials to propagate...")
                tries += 1
                if tries >= 6:
                    status("Azure credentials did not propagate in time, exiting...", True)
                    break
                time.sleep(5)

    if args.gcp:
        for project in args.gcp:
            if project == "None" or project == "":
              continue
            status(f"Getting GCP credentials for project {project}...")
            gcp_creds = vault_request(f'gcp/roleset/{vault_role}-{project}/key')
            gcp_creds = gcp_creds['data']['private_key_data']
            env_vars.append((f"TF_VAR_gcp_{project.replace('-', '_')}", gcp_creds))

    if args.terraform_registry:
        status("Getting Terraform registry token...")
        registry_data = vault_request(f'secret/applications/{args.name}/{args.env}/terraform-registry')
        registry_token = registry_data['data']['token']
        env_vars.append(("TF_TOKEN_terraform__registry_nrk_cloud", registry_token))
    
    if args.secret:
        status("Getting secrets from 'setenv'")
        secret_data = vault_request(f'secret/applications/{args.name}/{args.env}/setenv')
        for k, v in secret_data['data'].items():
            env_vars.append((k, v))
    
    if args.vault_secret:
        status("Getting secrets from vault...")
        for vault_secret in args.vault_secret:
            if vault_secret == "None":
                continue
            path, key, var_name = vault_secret.split(':')
            if key == '*':
                status(f"Fetching all keys from secret at {path}...")
                var_name = var_name or 'VAULT_SECRET_'
                
                secret_data = vault_request(path)
                for k, v in secret_data['data'].items():
                    status(f"Adding key '{var_name}{k}' to environment variables...")
                    env_vars.append((f"{var_name}{k}", v))
            
            else:
                status(f"Fetching key '{key}' from secret at {path}...")
                var_name = var_name or 'VAULT_SECRET'
            
            secret_data = vault_request(path)
            if key not in secret_data['data']:
                status(f"Key '{key}' not found in secret at {path}", True)
                continue
            
            env_vars.append((var_name, secret_data['data'][key]))

except urllib.error.HTTPError as e:
    status(f"HTTP Error: {e.code} - {e.reason}", True)
    status(f"Error response body: {e.read().decode()}", True)
    sys.exit(1)

status(f"Sleeping for {'0' if args.no_wait else '30'} seconds for azure and gcp credentials to propagate...")
time.sleep(0 if args.no_wait else 30)

set_credentials_cache(env_vars)

output_env_vars(env_vars)
