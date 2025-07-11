#!/bin/bash

VARIABLES="$(python3 /home/runuser/setenv.py)"

if [[ -z "$VARIABLES" ]]; then
  echo "No variables set. Exiting."
  exit 1
fi

eval "$VARIABLES"
