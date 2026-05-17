FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV CODEQL_HOME=/opt/codeql
ENV CODEQL_REPO=/opt/codeql-repo
ENV PATH="${CODEQL_HOME}:${PATH}"

RUN apt-get update && apt-get install -y \
    curl \
    unzip \
    git \
    ca-certificates \
    python3 \
    python3-pip \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

# Syft install
RUN curl -sSfL https://get.anchore.io/syft | sh -s -- -b /usr/local/bin

# Grype install
RUN curl -sSfL https://get.anchore.io/grype | sh -s -- -b /usr/local/bin

# CodeQL CLI install
RUN curl -L \
    https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-linux64.zip \
    -o /tmp/codeql.zip \
    && unzip /tmp/codeql.zip -d /opt \
    && rm /tmp/codeql.zip

# CodeQL queries/libraries install
RUN git clone --depth 1 https://github.com/github/codeql.git ${CODEQL_REPO}

# Query pack download
RUN codeql pack download codeql/javascript-queries

WORKDIR /workspace

CMD ["/bin/bash"]