FROM python:3.11

LABEL maintainer="Your Name <your@email.com>"

ENV COWRIE_GROUP=cowrie \
    COWRIE_USER=cowrie \
    COWRIE_HOME=/cowrie \
    PYTHONPATH=${COWRIE_HOME}/cowrie-git/src

# Installation des dépendances système
RUN apt-get update && \
    apt-get install -y sudo \
        git \
        libssl-dev \
        libffi-dev \
        procps \
        bash \
        libpcap-dev \
        iptables \
        at \
        sudo && \
        apt-get clean && \
    groupadd -r -g 1000 ${COWRIE_GROUP} && \
    useradd -r -u 1000 -d ${COWRIE_HOME} -m -g ${COWRIE_GROUP} ${COWRIE_USER} && \
    echo "${COWRIE_USER} ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers && \
    rm -rf /var/lib/apt/lists/*

# Installation de Cowrie
RUN git clone --separate-git-dir=/tmp/cowrie.git https://github.com/cowrie/cowrie ${COWRIE_HOME}/cowrie-git && \
    cd ${COWRIE_HOME} && \
    python -m venv cowrie-env && \
    . cowrie-env/bin/activate && \
    pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir --upgrade cffi && \
    pip install --no-cache-dir --upgrade setuptools && \
    pip install --no-cache-dir --upgrade -r ${COWRIE_HOME}/cowrie-git/requirements.txt && \
    pip install --no-cache-dir --upgrade -r ${COWRIE_HOME}/cowrie-git/requirements-output.txt

# Configuration des permissions
RUN chown -R ${COWRIE_USER}:${COWRIE_GROUP} ${COWRIE_HOME}

WORKDIR ${COWRIE_HOME}/cowrie-git

# Préservation du fichier de configuration par défaut
RUN cp etc/cowrie.cfg.dist etc/cowrie.cfg.dist.backup

VOLUME [ "/cowrie/cowrie-git/var", "/cowrie/cowrie-git/etc" ]

ENV PATH=${COWRIE_HOME}/cowrie-git/bin:${PATH} \
    COWRIE_STDOUT=yes

# Script de démarrage
COPY <<-'EOF' /entrypoint.sh
#!/bin/bash
source ${COWRIE_HOME}/cowrie-env/bin/activate
exec "$@"
EOF

RUN chmod +x /entrypoint.sh

RUN /entrypoint.sh

EXPOSE 2222 2223

# NIDS part
COPY . /app/

WORKDIR /app

RUN pip install -r requirements.txt

