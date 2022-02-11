import { hash, compare } from 'bcryptjs';
import { Session } from 'next-auth';
import { GetSessionParams, getSession as getSessionInner } from 'next-auth/react';

export async function hashPassword(password: string) {
  const hashedPassword = await hash(password, 12);
  return hashedPassword;
}

export async function verifyPassword(password: string, hashedPassword: string) {
  const isValid = await compare(password, hashedPassword);
  return isValid;
}

export async function getSession(options: GetSessionParams): Promise<Session | null> {
  const session = await getSessionInner(options);
  return session as Session | null;
}
