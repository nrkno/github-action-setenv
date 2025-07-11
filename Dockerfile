FROM python:3.13-alpine

RUN apk --no-cache add coreutils util-linux-misc bash && adduser -u 1001 -D runuser && pip3 install --no-cache-dir configargparse

USER runuser
ENV HOME=/home/runuser
COPY --chown=runuser:runuser setenv.py entrypoint.sh $HOME/
RUN chmod +x $HOME/setenv.py $HOME/entrypoint.sh

WORKDIR ${HOME}

ENTRYPOINT ["/home/runuser/entrypoint.sh"]