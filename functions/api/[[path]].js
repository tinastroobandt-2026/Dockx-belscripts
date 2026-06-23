// DOCKX Validatiedocument — Cloudflare Pages Functions backend
// Storage: D1 (binding "DB"), one row per topic. Auth: shared TEAM_PASSWORD.
//
// Routes (all under /api):
//   POST /api/login        { password }                  -> { ok }
//   GET  /api/state        (header x-team-pass)           -> { topics: { [topic]: data } }
//   POST /api/state        { topic, data } (header pass)  -> { ok }
//   POST /api/reset        (header pass)                  -> { ok }   (clears everything)
//
// D1 schema (created lazily on first call):
//   CREATE TABLE val_state (topic TEXT PRIMARY KEY, data TEXT, updated_at TEXT);

const JSON_HEADERS = { "Content-Type": "application/json" };

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: JSON_HEADERS });
}

async function ensureTable(db) {
  await db
    .prepare(
      "CREATE TABLE IF NOT EXISTS val_state (topic TEXT PRIMARY KEY, data TEXT, updated_at TEXT)"
    )
    .run();
}

function checkAuth(request, env) {
  const pass = request.headers.get("x-team-pass") || "";
  const expected = env.TEAM_PASSWORD || "";
  return expected !== "" && pass === expected;
}

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = url.pathname.replace(/^\/api\/?/, ""); // "" | "login" | "state" | "reset"
  const method = request.method.toUpperCase();

  // No DB binding configured yet
  if (!env.DB) {
    return json({ error: "no_db", message: "D1-binding 'DB' ontbreekt." }, 500);
  }

  try {
    await ensureTable(env.DB);
  } catch (e) {
    return json({ error: "db_init", message: String(e) }, 500);
  }

  // --- LOGIN ---
  if (path === "login") {
    if (method !== "POST") return json({ error: "method" }, 405);
    let body = {};
    try {
      body = await request.json();
    } catch (e) {}
    const expected = env.TEAM_PASSWORD || "";
    if (expected === "") return json({ ok: false, error: "no_password_set" }, 500);
    if ((body.password || "") === expected) return json({ ok: true });
    return json({ ok: false, error: "wrong_password" }, 401);
  }

  // Everything below requires auth — behalve beacon-POSTs (die authenticeren via de body)
  const isBeaconReq = url.searchParams.get("beacon") === "1" && method === "POST";
  if (!isBeaconReq && !checkAuth(request, env)) {
    return json({ error: "unauthorized" }, 401);
  }

  // --- GET STATE (all topics) ---
  if (path === "state" && method === "GET") {
    const rows = await env.DB.prepare("SELECT topic, data FROM val_state").all();
    const topics = {};
    for (const r of rows.results || []) {
      try {
        topics[r.topic] = JSON.parse(r.data);
      } catch (e) {
        topics[r.topic] = {};
      }
    }
    return json({ topics });
  }

  // --- POST STATE (one topic) ---
  if (path === "state" && method === "POST") {
    let body = {};
    try {
      body = await request.json();
    } catch (e) {
      return json({ error: "bad_json" }, 400);
    }
    // Beacon-verzoeken (paginaverlaten) kunnen geen header zetten: wachtwoord zit in de body
    const isBeacon = url.searchParams.get("beacon") === "1";
    if (isBeacon) {
      const expected = env.TEAM_PASSWORD || "";
      if (expected === "" || (body.pass || "") !== expected) {
        return json({ error: "unauthorized" }, 401);
      }
    } else if (!checkAuth(request, env)) {
      return json({ error: "unauthorized" }, 401);
    }
    const topic = body.topic;
    if (!topic || typeof topic !== "string") return json({ error: "no_topic" }, 400);
    const data = JSON.stringify(body.data || {});
    const now = new Date().toISOString();
    await env.DB.prepare(
      "INSERT INTO val_state (topic, data, updated_at) VALUES (?, ?, ?) " +
        "ON CONFLICT(topic) DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at"
    )
      .bind(topic, data, now)
      .run();
    return json({ ok: true, topic, updated_at: now });
  }

  // --- RESET (clear all) ---
  if (path === "reset" && method === "POST") {
    await env.DB.prepare("DELETE FROM val_state").run();
    return json({ ok: true });
  }

  return json({ error: "not_found", path }, 404);
}
