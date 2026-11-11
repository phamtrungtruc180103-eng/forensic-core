#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FABRIC_HOME="${FABRIC_HOME:?Set FABRIC_HOME to the fabric-samples directory}"
export PATH="${FABRIC_HOME}/bin:${PATH}"
export FABRIC_CFG_PATH="${FABRIC_HOME}/config"
export FABRIC_PEER_CLI="1"
export FABRIC_PEER_BIN="${FABRIC_HOME}/bin/peer"
export FABRIC_CHANNEL="${FABRIC_CHANNEL:-evidence-channel}"
export FABRIC_CHAINCODE="${FABRIC_CHAINCODE:-evidence}"
export COUCHDB_URL="${COUCHDB_URL:-http://localhost:5984}"
export COUCHDB_DATABASE="${COUCHDB_DATABASE:-forensic_core}"
export COUCHDB_USER="${COUCHDB_USER:?Set COUCHDB_USER}"
export COUCHDB_PASSWORD="${COUCHDB_PASSWORD:?Set COUCHDB_PASSWORD}"
export FABRIC_ORDERER_ADDRESS="${FABRIC_ORDERER_ADDRESS:-localhost:7050}"
export FABRIC_ORDERER_CA="${FABRIC_ORDERER_CA:-${FABRIC_HOME}/test-network/organizations/ordererOrganizations/example.com/tlsca/tlsca.example.com-cert.pem}"
export FABRIC_PEER_ADDRESSES="${FABRIC_PEER_ADDRESSES:-localhost:7051,localhost:9051}"
export FABRIC_PEER_TLS_ROOT_CERTS="${FABRIC_PEER_TLS_ROOT_CERTS:-${FABRIC_HOME}/test-network/organizations/peerOrganizations/org1.example.com/tlsca/tlsca.org1.example.com-cert.pem,${FABRIC_HOME}/test-network/organizations/peerOrganizations/org2.example.com/tlsca/tlsca.org2.example.com-cert.pem}"
export CORE_PEER_TLS_ENABLED="true"
export CORE_PEER_LOCALMSPID="Org1MSP"
export CORE_PEER_ADDRESS="${CORE_PEER_ADDRESS:-localhost:7051}"
export CORE_PEER_TLS_ROOTCERT_FILE="${CORE_PEER_TLS_ROOTCERT_FILE:-${FABRIC_HOME}/test-network/organizations/peerOrganizations/org1.example.com/tlsca/tlsca.org1.example.com-cert.pem}"
export CORE_PEER_MSPCONFIGPATH="${CORE_PEER_MSPCONFIGPATH:-${FABRIC_HOME}/test-network/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp}"

cd "${ROOT_DIR}"
umask 077
SECRETS_DIR="${ROOT_DIR}/.secrets"
JWT_SECRET_FILE="${SECRETS_DIR}/jwt_secret"
mkdir -p "${SECRETS_DIR}"
chmod 700 "${SECRETS_DIR}"
if [[ -z "${JWT_SECRET:-}" ]]; then
  if [[ ! -s "${JWT_SECRET_FILE}" ]]; then
    openssl rand -hex 48 > "${JWT_SECRET_FILE}"
    chmod 600 "${JWT_SECRET_FILE}"
  fi
  export JWT_SECRET="$(cat "${JWT_SECRET_FILE}")"
fi
"${ROOT_DIR}/.venv/bin/python" -m backend.security_bootstrap
echo "Checking CouchDB, Fabric peer, channel, and chaincode..."
"${ROOT_DIR}/.venv/bin/python" -m backend.fabric_preflight
exec "${ROOT_DIR}/.venv/bin/uvicorn" backend.main:app --host 0.0.0.0 --port 8000 --h11-max-incomplete-event-size 0
