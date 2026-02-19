#!/usr/bin/env bash
set -euo pipefail

# Create GitHub issues for Gateway Auth Enforcement Phase 1

gh issue create \
  --title "[GW-Auth Phase 1.1] Create security-requirements.ts module" \
  --label "security,gateway,breaking-change" \
  --body "## Context

Part of [Gateway Auth Enforcement Roadmap](https://github.com/openclaw/openclaw/blob/main/docs/security/GATEWAY_AUTH_ENFORCEMENT_ROADMAP.md) Phase 1.

Create the foundation module that defines and validates mandatory security configuration requirements.

## Acceptance Criteria

- [ ] Create \`src/config/security-requirements.ts\` with:
  - \`SecurityRequirement\` type definition
  - \`MANDATORY_SECURITY_REQUIREMENTS\` array with checks for:
    - \`gateway.auth.mode\` must be explicitly configured
    - \`gateway.auth.token|password\` credential must be present
    - \`gateway.securityConfigured\` flag must be true
  - \`validateSecurityRequirements()\` function
  - \`formatSecurityFailures()\` user-friendly error formatter
- [ ] Create \`src/config/security-requirements.test.ts\` with comprehensive test coverage
- [ ] All tests pass with 70%+ coverage

## Target Files

- \`src/config/security-requirements.ts\` (create)
- \`src/config/security-requirements.test.ts\` (create)

## Verification Commands

\`\`\`bash
pnpm tsgo
pnpm check
pnpm test src/config/security-requirements.test.ts
\`\`\`

## Assigned Agent

\`security-schema\`

## Dependencies

None (foundation phase)
"

gh issue create \
  --title "[GW-Auth Phase 1.2] Add securityConfigured flag to config schema" \
  --label "security,gateway,breaking-change" \
  --body "## Context

Part of [Gateway Auth Enforcement Roadmap](https://github.com/openclaw/openclaw/blob/main/docs/security/GATEWAY_AUTH_ENFORCEMENT_ROADMAP.md) Phase 1.

Add the \`gateway.securityConfigured\` boolean field to the config TypeBox schema. This flag must be explicitly set to \`true\` after security configuration is complete.

## Acceptance Criteria

- [ ] Add \`securityConfigured: Type.Optional(Type.Boolean({...}))\` to \`GatewayConfigSchema\` in \`src/config/config.ts\`
- [ ] Include clear description: \"Set to true after completing security configuration. Gateway will not start without this.\"
- [ ] Type checking passes (\`pnpm tsgo\`)
- [ ] Config schema tests updated if needed

## Target Files

- \`src/config/config.ts\`

## Verification Commands

\`\`\`bash
pnpm tsgo
pnpm check
pnpm test src/config/config.test.ts
\`\`\`

## Assigned Agent

\`security-schema\`

## Dependencies

Phase 1.1 (should be done in same PR)
"

echo "✓ Phase 1 issues created"
