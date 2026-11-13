FROM python:3.14-alpine@sha256:5862d971d1f0ae26b258cefa4e893556b1d3aba81bd2ff30888704ad378bab67

RUN apk --no-cache add coreutils util-linux-misc bash

COPY setenv.py entrypoint.sh /
RUN chmod +x /setenv.py /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
