# The Leopard - top-level convenience Makefile.
#
# Thin wrapper around docker compose and the offline-bundle scripts. The
# real work lives in the shell scripts; this Makefile just gives operators
# short, memorable entry points.

.DEFAULT_GOAL := help

# Use bash with strict flags so recipe failures surface immediately.
SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c

# Detect whether the invoking user can talk to docker directly, or whether
# they need sg(1) to pick up the docker group (common when a user was
# added to the group after their shell started). We prefer running bare
# docker when possible so output stays clean.
DOCKER_OK := $(shell docker info >/dev/null 2>&1 && echo yes || echo no)

ifeq ($(DOCKER_OK),yes)
  # docker is directly callable; build a trivial wrapper.
  compose = docker compose $(1)
else
  # Wrap every invocation in sg(1) so we pick up the docker group without
  # requiring the operator to re-login. Using single quotes around the
  # inner command keeps it robust against flags with spaces.
  compose = sg docker -c 'docker compose $(1)'
endif

.PHONY: help install install-proxy build up down logs bundle clean-bundle

help: ## List available targets
	@awk 'BEGIN { FS = ":.*?## " } \
	  /^[a-zA-Z0-9_.-]+:.*?## / { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } \
	  /^##@/ { printf "\n%s\n", substr($$0, 5) }' $(MAKEFILE_LIST)

##@ Install

install: ## Install with direct internet access (build + start)
	bash scripts/install.sh --direct

install-proxy: ## Install via HTTP proxy (install-time only). Usage: make install-proxy PROXY=http://10.5.13.13:8080 [NO_PROXY=...]
	@if [ -z "$(PROXY)" ]; then \
	  echo "Usage: make install-proxy PROXY=http://host:port [NO_PROXY=extra,hosts]"; \
	  echo "Example: make install-proxy PROXY=http://10.5.13.13:8080"; \
	  exit 1; \
	fi
	bash scripts/install.sh --proxy "$(PROXY)" $(if $(NO_PROXY),--no-proxy "$(NO_PROXY)",)

##@ Compose primitives

build: ## Build backend + frontend images (docker compose build)
	$(call compose,build)

up: ## Start the stack in the background
	$(call compose,up -d)

down: ## Stop and remove the stack (keeps volumes)
	$(call compose,down)

logs: ## Tail logs from all services (Ctrl-C to exit)
	$(call compose,logs -f)

##@ Offline bundle

bundle: ## Build a portable offline install tarball in dist/
	bash scripts/build-offline-bundle.sh

clean-bundle: ## Remove the dist/ directory (bundle output)
	rm -rf dist
