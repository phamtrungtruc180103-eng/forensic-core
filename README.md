# Forensic Core

An MVP for the research project **“Research and Application of Blockchain Technology in Digital Forensics”**, designed around the evidence-handling principles of ISO/IEC 27037.

## Running the Backend with Hyperledger Fabric

```bash
cd /path/to/forensic-core
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
cp .env.example .env

# Load .env with your preferred environment manager. Never commit the .env file.
export FABRIC_HOME=/path/to/fabric-samples
export COUCHDB_USER=your_couchdb_user
export COUCHDB_PASSWORD='use-a-strong-password'
export FABRIC_PEER_CLI=1
export FABRIC_PEER_BIN="$FABRIC_HOME/bin/peer"
export FABRIC_CFG_PATH="$FABRIC_HOME/config"
export FABRIC_CHANNEL=evidence-channel
export FABRIC_CHAINCODE=evidence
export FABRIC_ORDERER_ADDRESS=localhost:7050
export FABRIC_ORDERER_CA="$FABRIC_HOME/test-network/organizations/ordererOrganizations/example.com/tlsca/tlsca.example.com-cert.pem"
export FABRIC_PEER_ADDRESSES=localhost:7051,localhost:9051
export FABRIC_PEER_TLS_ROOT_CERTS="$FABRIC_HOME/test-network/organizations/peerOrganizations/org1.example.com/tlsca/tlsca.org1.example.com-cert.pem,$FABRIC_HOME/test-network/organizations/peerOrganizations/org2.example.com/tlsca/tlsca.org2.example.com-cert.pem"
export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_LOCALMSPID=Org1MSP
export CORE_PEER_ADDRESS=localhost:7051
export CORE_PEER_TLS_ROOTCERT_FILE="$FABRIC_HOME/test-network/organizations/peerOrganizations/org1.example.com/tlsca/tlsca.org1.example.com-cert.pem"
export CORE_PEER_MSPCONFIGPATH="$FABRIC_HOME/test-network/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp"
bash backend/run_fabric.sh
```

Open `http://localhost:8000` after the service starts.

When `FABRIC_PEER_CLI=1`, COLLECT, ACCESS, TRANSFER, RECEIVE, ANALYZE, and VERIFY operations, as well as evidence and history queries, are processed through the Fabric peer using the signed-in staff member's identity.

Metadata, ledger audits, projects, investigators, reports, verification records, and evidence relations are stored in the `forensic_core` CouchDB database. Original evidence files remain off-chain in `storage/`.

## Main API Endpoints

### Authentication and administration

- `POST /api/auth/register`: creates a standard operational account; self-registration cannot create an `ADMIN` account.
- `POST /api/auth/login`: authenticates with a username, password, and operational position, then returns a JWT bearer token.
- `GET /api/auth/me`: returns the currently authenticated account.
- `POST /api/auth/change-password`: changes the authenticated account password and clears the bootstrap password requirement.
- `GET/POST /api/admin/users`: allows an administrator to list and create user accounts.

### Evidence

- `POST /api/evidence`: accepts multipart fields `file`, `case_id`, `investigator_id`, `evidence_type`, `source`, `acquisition_method`, and `collected_at`; calculates SHA-256 from the uploaded bytes and stores the original file off-chain.
- `GET /api/evidence`: lists evidence records.
- `GET /api/evidence?case_id=CASE-...`: performs a CouchDB rich query by case when Fabric mode is enabled.
- `GET /api/evidence/{id}/history`: returns the complete chain-of-custody history.
- `PUT /api/evidence/{id}`: updates evidence metadata; fields committed to Fabric are immutable in Fabric mode.
- `DELETE /api/evidence/{id}`: marks evidence as `DELETED` on the ledger and removes the off-chain file while preserving its history.
- `POST /api/evidence/{id}/verify`: recalculates SHA-256 and the Merkle root, returns `MATCH`, `MISMATCH`, or `NOT_VERIFIED`, and records a VERIFY event on Fabric.
- `POST /api/evidence/{id}/access`: records an ACCESS event with `actor_id` and `reason`.
- `POST /api/evidence/{id}/transfer`: records a TRANSFER event with `from_holder`, `to_holder`, `actor_id`, and `reason`.
- `POST /api/evidence/{id}/receive`: records confirmation that the recipient has received the evidence.
- `POST /api/evidence/{id}/analyze`: records the analysis reason and result.

The **Evidence Transfer** interface lets users select evidence and record the sender, recipient, and acting staff member. These details become part of the custody history.

### System and project data

- `GET /api/health`: checks CouchDB, the Fabric peer, channel, and chaincode; returns HTTP `503` when Fabric is unavailable.
- `GET/POST /api/projects`: lists and creates projects.
- `GET/POST /api/investigators`: lists investigators or creates a staff profile and linked account. Creation requires `username`, `password`, `enrollmentID`, and `organization`. In Fabric mode, `RegisterStaff` must commit successfully before the investigator is persisted to CouchDB.
- `PUT /api/investigators/{id}`: updates staff details or roles as an administrator and synchronizes role changes with the ledger.
- `PATCH /api/investigators/{id}/status`: locks or unlocks the application account and can optionally revoke the Fabric identity.
- `GET /api/investigators/{id}/fabric-identity`: compares the local wallet, application status, and Staff record on the ledger.
- `DELETE /api/investigators/{id}`: locks the account, runs `DeactivateStaff`, revokes the Fabric CA identity, and preserves the profile for auditing.
- `GET/POST /api/reports`: lists and creates reports.
- `GET /api/reports/{id}/pdf`: generates a PAdES-B-B signed PDF using the authenticated user's Fabric MSP identity.
- `GET/POST /api/relations`: lists and creates evidence-graph relations.

## JSON-to-CouchDB Migration

```bash
cd /path/to/forensic-core
.venv/bin/python -m backend.migrate_json_to_couch
```

The migration script creates a timestamped backup under `storage/json-backup-*` and does not delete the original JSON files.

## Fabric Chaincode

```bash
cd chaincode
go mod tidy
gofmt -w evidence.go
go test ./...
```

The contract provides the following transactions:

- `RecordEvidence`
- `RecordCustodyEvent`
- `QueryEvidence`
- `QueryHistory`
- `QueryEvidenceByCase`
- `QueryAllEvidence`
- `RegisterStaff`
- `UpdateStaffRole`
- `DeactivateStaff`
- `QueryStaff`

The chaincode reads the Common Name, MSP, and `staffID` attribute from the caller's certificate. It validates the caller's role and status against the Staff record on the ledger and rejects mismatched or revoked identities.

When staff are created in Fabric mode, the backend uses the CA administrator to register and enroll the requested `enrollmentID` through `fabric-ca-client`. It creates a separate restricted-permission wallet under `.fabric-wallets/`. CouchDB stores only the `walletReference`, never the private key.

Administrative Staff transactions are signed by the Fabric administrator. Operational transactions are signed using the wallet belonging to the authenticated staff member. Ledger records include `signerID`, `signerMSP`, and `lastTxID`. Block number, validation code, block hash, and previous block hash are resolved from the exact transaction block through QSCC rather than inferred from the current chain height.

Revoking an identity updates the Staff record, revokes the certificate through Fabric CA, and publishes the generated CRL into the channel MSP configuration. The backend checks CRL validity hourly and refreshes it before expiration.

The `evidence` chaincode must be deployed on `evidence-channel` before the backend starts. `backend/run_fabric.sh` performs startup checks for CouchDB, the Fabric peer, channel, and chaincode before starting Uvicorn.

If Fabric environment variables are not enabled, the backend uses the `local-adapter` ledger implementation. CouchDB is still required for metadata and operational data.

## Testing

```bash
cd /path/to/forensic-core
.venv/bin/python -m unittest discover -s tests -p "test_*.py" -v
node --check frontend/js/dashboard.js

cd chaincode
go test ./...
```

To run the optional PDF signing test with a Fabric MSP identity, set `TEST_PDF_MSP_PATH` to a valid MSP directory containing the certificate and private key.

## Security Notes

- Never commit `.env`, `.secrets/`, `.fabric-wallets/`, or evidence files from `storage/`.
- Use a strong, unique CouchDB password and do not expose CouchDB directly to an untrusted network.
- If `JWT_SECRET` is not supplied, the application generates a persistent secret in `.secrets/jwt_secret` with restricted permissions.
- The security bootstrap creates or rotates the administrator without a fixed default password. A generated initial password is written to `.secrets/admin_initial_password` with mode `0600` and removed after the password is changed.
- New accounts require passwords containing at least 12 characters.
- Configure `CORS_ALLOWED_ORIGINS` for the actual frontend origins used in deployment.
- Use TLS or a trusted reverse proxy when exposing the application outside localhost.

## Environment Requirements

- Windows 11 with WSL2 Ubuntu, or a compatible Linux environment
- Python 3.11 or later
- Go 1.21 or later
- Node.js 20 or later for JavaScript syntax checking
- Docker Desktop with WSL2 integration when running the Fabric test network

## License

No open-source license is granted for this repository. All rights are reserved. Public availability of the source code does not grant permission to copy, modify, distribute, or use it beyond rights provided by applicable law.
