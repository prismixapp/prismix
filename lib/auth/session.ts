import { DefaultSession } from "next-auth";
import {
  getSession as getNextSession,
  GetSessionParams,
} from "next-auth/react";

type DefaultSessionUser = NonNullable<DefaultSession["user"]>;

type SessionUser = DefaultSessionUser & {
  id: string;
};

export type Session = DefaultSession & {
  user?: SessionUser;
};

export async function getSession(
  options: GetSessionParams
): Promise<Session | null> {
  const session = await getNextSession(options);

  return session as Session | null;
}
