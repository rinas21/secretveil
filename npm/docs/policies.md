# Policies

## Overview

Secret policies control which secrets can be injected into applications, providing an additional layer of security.

## Usage

```bash
secretveil policy create backend API_KEY DB_PASSWORD JWT_SECRET
secretveil policy create worker API_KEY
secretveil policy create frontend PUBLIC_API_URL
secretveil policy list
secretveil run --policy backend npm start
```

## Policy Structure

Policies are stored in `.secretveil/policies.json`:
```json
{
  "backend": {
    "allow": ["API_KEY", "DB_PASSWORD", "JWT_SECRET"]
  },
  "worker": {
    "allow": ["API_KEY"]
  },
  "frontend": {
    "allow": ["PUBLIC_API_URL"]
  }
}
```

## Policy Enforcement

When using `--policy`:
1. Only the specified secrets are injected
2. Secrets outside the policy are NOT injected
3. If the application requests a forbidden secret, it will fail safely
4. No silent injection of all available secrets when a restrictive policy exists

## Policy Validation

Policies are validated on creation:
- At least one secret name is required
- Duplicate policy names are rejected
- Policy references must be valid

## Policy Examples

### Backend Service
```bash
secretveil policy create backend API_KEY DB_PASSWORD JWT_SECRET
secretveil run --policy backend node server.js
```

### Worker Service
```bash
secretveil policy create worker API_KEY
secretveil run --policy worker node worker.js
```

### Frontend Application
```bash
secretveil policy create frontend PUBLIC_API_URL
secretveil run --policy frontend node client.js
```

## Security Benefits

1. **Least privilege**: Applications only receive the secrets they need
2. **Accidental injection prevention**: No silent injection of all secrets
3. **Policy-based access control**: Clear separation of concerns
4. **Auditability**: Policy usage can be tracked in audit logs

## Best Practices

1. Create separate policies for each application
2. Only allow necessary secrets
3. Review policies regularly
4. Use `--policy` flag explicitly
5. Document which secrets each policy allows

## Future Enhancements

- Profile-level policies
- Policy versioning
- Policy inheritance
- Policy access logs
