#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FABRIC_HOME="${FABRIC_HOME:?Set FABRIC_HOME to the fabric-samples directory}"
CHANNEL_NAME="${FABRIC_CHANNEL:-evidence-channel}"
ORG_MSP="${CORE_PEER_LOCALMSPID:-Org1MSP}"
CRL_FILE="${FABRIC_ORG_CRL:-${FABRIC_HOME}/test-network/organizations/peerOrganizations/org1.example.com/msp/crls/crl.pem}"
ORDERER_CA="${FABRIC_ORDERER_CA:-${FABRIC_HOME}/test-network/organizations/ordererOrganizations/example.com/tlsca/tlsca.example.com-cert.pem}"
ORDERER_ADDRESS="${FABRIC_ORDERER_ADDRESS:-localhost:7050}"
PEER_BIN="${FABRIC_PEER_BIN:-${FABRIC_HOME}/bin/peer}"
CONFIGTXLATOR_BIN="${CONFIGTXLATOR_BIN:-${FABRIC_HOME}/bin/configtxlator}"
WORK_ROOT="${ROOT_DIR}/.fabric-tmp"
mkdir -p "${WORK_ROOT}"
WORK_DIR="$(mktemp -d "${WORK_ROOT}/crl-update.XXXXXX")"
trap 'rm -rf "${WORK_DIR}"' EXIT

if [[ ! -s "${CRL_FILE}" ]]; then
  echo "CRL file is missing or empty: ${CRL_FILE}" >&2
  exit 1
fi

export FABRIC_CFG_PATH="${FABRIC_HOME}/config"
export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_LOCALMSPID="${ORG_MSP}"
export CORE_PEER_ADDRESS="${CORE_PEER_ADDRESS:-localhost:7051}"
export CORE_PEER_TLS_ROOTCERT_FILE="${CORE_PEER_TLS_ROOTCERT_FILE:-${FABRIC_HOME}/test-network/organizations/peerOrganizations/org1.example.com/tlsca/tlsca.org1.example.com-cert.pem}"
export CORE_PEER_MSPCONFIGPATH="${CORE_PEER_MSPCONFIGPATH:-${FABRIC_HOME}/test-network/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp}"

"${PEER_BIN}" channel fetch config "${WORK_DIR}/config_block.pb" \
  -o "${ORDERER_ADDRESS}" --ordererTLSHostnameOverride orderer.example.com \
  -c "${CHANNEL_NAME}" --tls --cafile "${ORDERER_CA}"

"${CONFIGTXLATOR_BIN}" proto_decode --input "${WORK_DIR}/config_block.pb" --type common.Block --output "${WORK_DIR}/config_block.json"
jq '.data.data[0].payload.data.config' "${WORK_DIR}/config_block.json" > "${WORK_DIR}/config.json"
CRL_BASE64="$(base64 -w 0 "${CRL_FILE}")"
jq --arg crl "${CRL_BASE64}" \
  ".channel_group.groups.Application.groups.${ORG_MSP}.values.MSP.value.config.revocation_list = [\$crl]" \
  "${WORK_DIR}/config.json" > "${WORK_DIR}/modified_config.json"

"${CONFIGTXLATOR_BIN}" proto_encode --input "${WORK_DIR}/config.json" --type common.Config --output "${WORK_DIR}/config.pb"
"${CONFIGTXLATOR_BIN}" proto_encode --input "${WORK_DIR}/modified_config.json" --type common.Config --output "${WORK_DIR}/modified_config.pb"
"${CONFIGTXLATOR_BIN}" compute_update --channel_id "${CHANNEL_NAME}" --original "${WORK_DIR}/config.pb" --updated "${WORK_DIR}/modified_config.pb" --output "${WORK_DIR}/config_update.pb"
"${CONFIGTXLATOR_BIN}" proto_decode --input "${WORK_DIR}/config_update.pb" --type common.ConfigUpdate --output "${WORK_DIR}/config_update.json"

jq -n --arg channel "${CHANNEL_NAME}" --slurpfile update "${WORK_DIR}/config_update.json" \
  '{payload:{header:{channel_header:{channel_id:$channel,type:2}},data:{config_update:$update[0]}}}' \
  > "${WORK_DIR}/config_update_envelope.json"
"${CONFIGTXLATOR_BIN}" proto_encode --input "${WORK_DIR}/config_update_envelope.json" --type common.Envelope --output "${WORK_DIR}/config_update_envelope.pb"

"${PEER_BIN}" channel update -f "${WORK_DIR}/config_update_envelope.pb" \
  -c "${CHANNEL_NAME}" -o "${ORDERER_ADDRESS}" --ordererTLSHostnameOverride orderer.example.com \
  --tls --cafile "${ORDERER_CA}"

echo "Org1 MSP CRL was committed to channel ${CHANNEL_NAME}"
