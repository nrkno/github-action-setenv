FROM python:3.14-alpine@sha256:5862d971d1f0ae26b258cefa4e893556b1d3aba81bd2ff30888704ad378bab67

COPY setenv.py /setenv.py
RUN chmod 0755 /setenv.py

# setenv.py reads its configuration from INPUT_* and writes GITHUB_ENV / GITHUB_OUTPUT itself.
ENTRYPOINT ["python3", "/setenv.py"]
