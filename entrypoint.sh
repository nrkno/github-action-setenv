#!/bin/bash
set -x

env | sort

if [[ "$@" == "" ]]; then
  echo "No arguments provided. Please provide arguments to setenv.py."
  echo "Minimum --name and --env is required."
  exit 1
fi

# Preprocess --cluster, --gcp, --vault-secret, and boolean flags
args=()
while [[ $# -gt 0 ]]; do
  if [[ $1 == "--cluster" || $1 == "--gcp" || $1 == "--vault-secret" ]]; then
    IFS=',' read -ra values <<<"$2"
    for value in "${values[@]}"; do
      if [[ -n "${value// /}" ]]; then
        args+=("$1" "$value")
      fi
    done
    shift 2
  elif [[ $1 == "--azure" || $1 == "--azure-no-arm" || $1 == "--terraform-registry" || $1 == "--no-wait" || $1 == "--eval" || $1 == "--new-line" || $1 == "--debug" || $1 == "--cache" ]]; then
    if [[ "$2" == "true" ]]; then
      args+=("$1")
    fi
    shift 2
  else
    args+=("$1")
    shift
  fi
done

/home/runuser/setenv.py "${args[@]}"
