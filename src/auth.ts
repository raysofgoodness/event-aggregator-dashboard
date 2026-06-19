import { D1Adapter } from "@auth/d1-adapter";
import { getCloudflareContext } from "@opennextjs/cloudflare";
import bcrypt from "bcryptjs";
import NextAuth from "next-auth";
import Credentials from "next-auth/providers/credentials";

interface DashboardUser {
  id: string;
  email: string;
  name: string | null;
  passwordHash?: string | null;
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

export const { handlers, auth, signIn, signOut } = NextAuth(async () => {
  const { env } = await getCloudflareContext({ async: true });

  if (!env.DB) {
    throw new Error("D1 binding DB is not configured");
  }

  return {
    adapter: D1Adapter(env.DB),
    providers: [
      Credentials({
        credentials: {
          email: { label: "Email", type: "email" },
          password: { label: "Password", type: "password" },
        },
        async authorize(credentials) {
          const email = credentials?.email;
          const password = credentials?.password;

          if (!isNonEmptyString(email) || !isNonEmptyString(password)) {
            return null;
          }

          const user = await env.DB.prepare(
            "SELECT id, email, name, passwordHash FROM users WHERE email = ?",
          )
            .bind(email)
            .first<DashboardUser>();

          if (!user?.passwordHash) {
            return null;
          }

          const valid = await bcrypt.compare(password, user.passwordHash);
          if (!valid) {
            return null;
          }

          return {
            id: user.id,
            email: user.email,
            name: user.name ?? undefined,
          };
        },
      }),
    ],
    session: { strategy: "jwt" },
    pages: { signIn: "/login" },
    trustHost: true,
  };
});
