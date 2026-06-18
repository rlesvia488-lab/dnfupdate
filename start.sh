#!/bin/bash
set -euo pipefail

# Source global environment variables when present.
[ -f /etc/environment ] && source /etc/environment
[ -f /etc/profile.d/java_home.sh ] && source /etc/profile.d/java_home.sh

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JAR_PATH="${APP_DIR}/dnf-security-update-console.jar"
LOGS_DIR_ROOT="${LOGS_DIR_ROOT:-${APP_DIR}/logs}"
NAME_APP="${NAME_APP:-dnf-security-update-console}"
APP_PORT="${APP_PORT:-8080}"

# Observability parameters from the standard service launcher.
export OTEL_EXPORTER_OTLP_ENDPOINT="${OTEL_EXPORTER_OTLP_ENDPOINT:-http://localhost:4317}"
export OTEL_LOGS_EXPORTER="${OTEL_LOGS_EXPORTER:-otlp}"
export OTEL_METRICS_EXPORTER="${OTEL_METRICS_EXPORTER:-otlp}"
export OTEL_RESOURCE_ATTRIBUTES="${OTEL_RESOURCE_ATTRIBUTES:-service.name=${TRIGRAM:-dnf}-${COMPONENT:-update}-${ENV:-local},service.version=${ARTIFACT_VERSION:-local}}"
export JAVA_VERSION="${JAVA_VERSION:-17}"

# Vault parameters. Set these before running start.sh or edit the defaults here.
export VAULT_ENABLED="${VAULT_ENABLED:-true}"
if [ "${VAULT_ENABLED}" = "true" ]; then
  export VAULT_URI="${VAULT_URI:?Set VAULT_URI, for example https://vault.example.com}"
  export VAULT_ROLE_ID="${VAULT_ROLE_ID:?Set VAULT_ROLE_ID}"
  export VAULT_SECRET_ID="${VAULT_SECRET_ID:?Set VAULT_SECRET_ID}"
  export CMAAS_OAUTH_TOKEN_URL="${CMAAS_OAUTH_TOKEN_URL:?Set CMAAS_OAUTH_TOKEN_URL}"
  export OCS_SERVERS_URL="${OCS_SERVERS_URL:?Set OCS_SERVERS_URL}"
  export OCS_SERVER_ACTION_URL="${OCS_SERVER_ACTION_URL:?Set OCS_SERVER_ACTION_URL}"
else
  export VAULT_URI="${VAULT_URI:-}"
  export VAULT_ROLE_ID="${VAULT_ROLE_ID:-}"
  export VAULT_SECRET_ID="${VAULT_SECRET_ID:-}"
  export CMAAS_OAUTH_TOKEN_URL="${CMAAS_OAUTH_TOKEN_URL:-}"
  export OCS_SERVERS_URL="${OCS_SERVERS_URL:-}"
  export OCS_SERVER_ACTION_URL="${OCS_SERVER_ACTION_URL:-}"
fi
export VAULT_CONTEXT="${VAULT_CONTEXT:-${TRIGRAM:-dnf}/${COMPONENT:-update}/${ENV:-local}/default}"
export VAULT_NAMESPACE="${VAULT_NAMESPACE:-myVault/${VAULT_NAMESPACE_VALUE:-default}}"
export VAULT_TECH_ACCOUNTS_PATH="${VAULT_TECH_ACCOUNTS_PATH:-${VAULT_CONTEXT}}"

JVM_MIN="${JVM_MIN:-256m}"
JVM_MAX="${JVM_MAX:-512m}"
PROFILE="${PROFILE:-default}"
UNIBANK_SERVICE_VERSION="${UNIBANK_SERVICE_VERSION:-${ARTIFACT_VERSION:-local}}"
JWK_LOCATION="${JWK_LOCATION:-}"
AGENTS_DIR="${AGENTS_DIR:-${APP_DIR}/agents}"

mkdir -p "${LOGS_DIR_ROOT}/${NAME_APP}"

JAVA_AGENT_ARGS=()
if [ -f "${AGENTS_DIR}/otel.jar" ]; then
  JAVA_AGENT_ARGS+=("-javaagent:${AGENTS_DIR}/otel.jar")
fi
if [ -f "${AGENTS_DIR}/jmx-exporter.jar" ] && [ -f "${AGENTS_DIR}/jmx_config.yaml" ]; then
  JAVA_AGENT_ARGS+=("-javaagent:${AGENTS_DIR}/jmx-exporter.jar=8081:${AGENTS_DIR}/jmx_config.yaml")
fi

SECURITY_ARGS=()
if [ -n "${JWK_LOCATION}" ]; then
  SECURITY_ARGS+=("-Dunibank.service.security.jwk-location=${JWK_LOCATION}")
fi

export DNF_UPDATE_PORT="${APP_PORT}"

exec java -server "-Xms${JVM_MIN}" "-Xmx${JVM_MAX}" \
  "${JAVA_AGENT_ARGS[@]}" \
  -Dspring.application.name="${NAME_APP}" \
  -Dspring.cloud.vault.authentication=approle \
  -Dspring.cloud.vault.enabled="${VAULT_ENABLED}" \
  -Dspring.profiles.active="${PROFILE}" \
  -Dspring.cloud.vault.fail-fast=true \
  -Dspring.cloud.vault.kv.enabled=true \
  -Dspring.cloud.vault.kv.default-context="${VAULT_CONTEXT}" \
  -Dspring.cloud.vault.uri="${VAULT_URI}" \
  -Dspring.cloud.vault.app-role.role-id="${VAULT_ROLE_ID}" \
  -Dspring.cloud.vault.app-role.secret-id="${VAULT_SECRET_ID}" \
  -Dspring.cloud.vault.connection-timeout=5000 \
  -Dspring.cloud.vault.read-timeout=15000 \
  -Dspring.cloud.vault.config.order=-10 \
  -Dspring.cloud.vault.namespace="${VAULT_NAMESPACE}" \
  -Ddnfupdate.vault.technical-accounts-path="${VAULT_TECH_ACCOUNTS_PATH}" \
  -Ddnfupdate.cmaas.oauth-token-url="${CMAAS_OAUTH_TOKEN_URL}" \
  -Ddnfupdate.ocs.servers-url="${OCS_SERVERS_URL}" \
  -Ddnfupdate.ocs.server-action-url="${OCS_SERVER_ACTION_URL}" \
  -Dunibank.service.version="${UNIBANK_SERVICE_VERSION}" \
  "${SECURITY_ARGS[@]}" \
  -jar "${JAR_PATH}" \
  --server.port="${APP_PORT}" \
  --logging.file.name="${LOGS_DIR_ROOT}/${NAME_APP}/service.log"
