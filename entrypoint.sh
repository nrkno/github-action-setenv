#!/bin/bash

if [[ -v "${INPUT_VAULT_SECRET}" ]]; then
  IFS=',' read -ra SECRET_ENTRIES <<< "$INPUT_VAULT_SECRET"
  vault_entries=""
  for ENTRY in "${SECRET_ENTRIES[@]}"; do
    echo "Processing vault secret entry: $ENTRY"
    vault_entry=" --vault-secret \"$ENTRY\""
    vault_entries="${vault_entries} ${vault_entry}"
  done
fi

if [[ -v "${INPUT_GCP}" ]]; then
  IFS=',' read -ra GCP_ENTRIES <<< "$INPUT_GCP"
  gcp_entries=""
  for ENTRY in "${GCP_ENTRIES[@]}"; do
    echo "Processing gcp project entry: $ENTRY"
    gcp_entry=" --gcp \"$ENTRY\""
    gcp_entries="${gcp_entries}${gcp_entry}"
  done
fi

VARIABLES="$(python3 /setenv.py${vault_entries}${gcp_entries})"

if [[ -z "$VARIABLES" ]]; then
  echo "No variables set. Exiting."
  exit 1
fi

eval "$VARIABLES"
