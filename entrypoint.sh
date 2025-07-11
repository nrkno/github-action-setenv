#!/bin/bash
set -e
set -x

pipenv run bin/setenv.py $@
