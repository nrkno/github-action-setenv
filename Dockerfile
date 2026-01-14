FROM python:3.13-alpine

RUN apk --no-cache add coreutils util-linux-misc bash && pip3 install --no-cache-dir configargparse

COPY setenv.py entrypoint.sh /
RUN chmod +x /setenv.py /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]