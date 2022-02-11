import NextAuth from 'next-auth';
import CredentialsProvider from 'next-auth/providers/credentials';
import { PrismaAdapter } from '@next-auth/prisma-adapter';

import { verifyPassword, hashPassword } from '@lib/auth';
import { Session } from '@lib/auth/session';
import { prisma } from '@db/index';

export default NextAuth({
  adapter: PrismaAdapter(prisma),
  secret: process.env.JWT_SECRET,
  session: {
    strategy: 'jwt',
  },
  pages: {
    signIn: '/auth',
  },
  providers: [
    CredentialsProvider({
      id: 'credentials',
      type: 'credentials',
      name: 'Prismix',
      credentials: {
        email: {
          label: 'Email Address',
          type: 'email',
        },
        password: {
          label: 'Password',
          type: 'password',
        },
      },
      async authorize(credentials) {
        try {
          let user = await prisma.user.findFirst({
            where: {
              email: credentials!.email.toLocaleLowerCase(),
            },
            select: {
              id: true,
              email: true,
              password: true,
              username: true,
            },
          });

          if (!user) {
            if (!credentials!.password || !credentials!.email) {
              throw new Error('Invalid Credentials');
            }

            user = await prisma.user.create({
              data: {
                username: credentials!.email.split('@')[0],
                email: credentials!.email,
                password: await hashPassword(credentials!.password),
              },
              select: {
                id: true,
                email: true,
                password: true,
                username: true,
              },
            });
          } else {
            const isValid = await verifyPassword(credentials!.password, user.password);

            if (!isValid) {
              throw new Error('Invalid Credentials');
            }
          }

          return {
            id: user.id,
            email: user.email,
            username: user.username,
          };
        } catch (error) {
          console.log(error);
          throw error;
        }
      },
    }),
  ],
  callbacks: {
    async jwt({ token, user }) {
      if (user) {
        token.id = user.id;
        token.email = user.email;
      }

      return token;
    },
    async signIn({}) {
      return true;
    },
    async session({ session, token }) {
      const prismixSession: Session = {
        ...session,
        user: {
          ...session.user,
          id: token.id as string,
          email: token.email as string,
        },
      };

      return prismixSession;
    },
  },
});
