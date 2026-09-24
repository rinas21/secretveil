let _cachedSession = null;

export function createSession(projectDir, config, secretsData, dek) {
  _cachedSession = {
    projectDir,
    config,
    secretsData,
    dek: dek ? Buffer.from(dek) : null,
    createdAt: Date.now()
  };
  return _cachedSession;
}

export function getSession() {
  return _cachedSession;
}

export function clearSession() {
  _cachedSession = null;
}

export function invalidateSession() {
  _cachedSession = null;
}

export function hasSession() {
  return _cachedSession !== null;
}

export function getSessionDEK() {
  const session = _cachedSession;
  if (!session || !session.dek) return null;
  return session.dek;
}
