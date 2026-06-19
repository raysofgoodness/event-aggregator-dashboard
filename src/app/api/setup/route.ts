import { up } from "@auth/d1-adapter";
import type { D1Database } from "@auth/d1-adapter";
import { getCloudflareContext } from "@opennextjs/cloudflare";

async function waitForUsersTable(
  db: D1Database,
  maxAttempts = 20,
): Promise<void> {
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const table = await db
      .prepare(
        "SELECT 1 AS ok FROM sqlite_master WHERE type = 'table' AND name = 'users'",
      )
      .first<{ ok: number }>();

    if (table) return;

    await new Promise((resolve) => setTimeout(resolve, 50));
  }

  throw new Error("users table was not created");
}

async function runAuthMigrations(db: D1Database): Promise<void> {
  await up(db);
  await waitForUsersTable(db);
}

async function ensurePasswordHashColumn(db: D1Database): Promise<void> {
  const result = await db
    .prepare("PRAGMA table_info(users)")
    .all<{ name: string }>();

  const hasPasswordHash = result.results?.some(
    (column: { name: string }) => column.name === "passwordHash",
  );

  if (!hasPasswordHash) {
    await db.prepare("ALTER TABLE users ADD COLUMN passwordHash TEXT").run();
  }
}

export async function GET() {
  try {
    const { env } = await getCloudflareContext({ async: true });

    if (!env.DB) {
      return Response.json(
        { ok: false, error: "D1 binding DB is not configured" },
        { status: 500 },
      );
    }

    await runAuthMigrations(env.DB);
    await ensurePasswordHashColumn(env.DB);

    return Response.json({
      ok: true,
      message: "Auth.js D1 tables initialized",
    });
  } catch (error) {
    console.error("Setup failed:", error);
    return Response.json(
      { ok: false, error: "Failed to initialize database" },
      { status: 500 },
    );
  }
}
