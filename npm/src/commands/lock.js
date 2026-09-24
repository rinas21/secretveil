import { hasSession, invalidateSession } from '../session/session.js';

export async function lock(args) {
  if (!hasSession()) {
    throw new Error('SecretVeil is not unlocked.');
  }
  invalidateSession();
  console.log('SecretVeil locked.');
}
