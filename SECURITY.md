# Security Policy

## Supported version

Security fixes are applied to the latest revision on the default branch.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability, leaked credential, private key, or evidence disclosure.

Use the repository's **Security** tab to submit a private vulnerability report through GitHub Private Vulnerability Reporting. Include:

- the affected endpoint, component, or chaincode transaction;
- reproduction steps and the expected security boundary;
- potential impact on evidence integrity, identity, custody history, or secrets;
- any suggested mitigation, if available.

Remove real evidence, credentials, certificates, private keys, JWTs, and personal data from reports. Use synthetic identifiers and hashes instead.

## Operational security

- Never commit `.env`, `.secrets/`, `.fabric-wallets/`, or `storage/` contents.
- Rotate a credential immediately if it is exposed, then update the Fabric CA CRL and channel MSP configuration when a Fabric identity is involved.
- Place the API behind HTTPS or a trusted TLS reverse proxy outside local development.
- Restrict CouchDB, Fabric CA, peer, and orderer ports to trusted networks.
