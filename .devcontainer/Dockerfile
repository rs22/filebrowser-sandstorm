# See here for image contents: https://github.com/microsoft/vscode-dev-containers/tree/v0.245.0/containers/alpine/.devcontainer/base.Dockerfile

# [Choice] Alpine version: 3.16, 3.15, 3.14, 3.13
ARG VARIANT="3.16"
FROM mcr.microsoft.com/vscode/devcontainers/base:0-alpine-${VARIANT}

RUN apk update \
    && apk add --no-cache npm make ncurses

COPY --from=golang:1.18-alpine /usr/local/go/ /usr/local/go/

ENV PATH="/usr/local/go/bin:${PATH}"
