# Security policy for the research prototype

S-BFP is an experimental implementation and must not be used as the sole factor
for production authentication.

The checked-in server and Flask session secrets are public demonstration values.
For any non-local deployment, provide unique high-entropy values through
`S_BFP_SERVER_SECRET` and `S_BFP_SESSION_SECRET`, terminate TLS at a trusted
reverse proxy, restrict network access, and review the data retention policy.

Raw fingerprint collection and direct client metadata are disabled by default.
Do not enable `S_BFP_STORE_RAW_FINGERPRINT` or
`S_BFP_STORE_CLIENT_METADATA` without explicit participant consent and an
approved handling plan.

Please report vulnerabilities privately to the authors through the contact
channel listed in the camera-ready artifact. No public contact is included in the
anonymous-review version.
