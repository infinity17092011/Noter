// MyJarvis backend: Express + Supabase + PayPal (no webhooks) + Groq
// Node 18+ (uses the built-in fetch)

const express = require("express");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const { createClient } = require("@supabase/supabase-js");

const {
  PORT = 3000,
  ALLOWED_ORIGIN,
  GROQ_API_KEY,
  GROQ_MODEL = "openai/gpt-oss-20b",
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  PAYPAL_CLIENT_ID,
  PAYPAL_CLIENT_SECRET,
  PAYPAL_PLAN_ID,
  PAYPAL_ENV = "sandbox",
} = process.env;

for (const [k, v] of Object.entries({
  ALLOWED_ORIGIN, GROQ_API_KEY, SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY,
  PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET, PAYPAL_PLAN_ID,
})) {
  if (!v) console.warn("Missing environment variable: " + k);
}

const PAYPAL_BASE =
  PAYPAL_ENV === "live" ? "https://api-m.paypal.com" : "https://api-m.sandbox.paypal.com";
const TABLE = "subscriptions"; // user_id (unique), paypal_subscription_id (unique), status, next_billing_time, last_checked
const MAX_NOTES = 20000;
const RECHECK_MS = 5 * 60 * 1000; // how stale a saved status may be before asking PayPal again

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false },
});

const app = express();
app.set("trust proxy", 1); // Render sits behind a proxy
app.use(cors({ origin: ALLOWED_ORIGIN, allowedHeaders: ["Content-Type", "Authorization"] }));
app.use(express.json({ limit: "100kb" }));

/* ---------- Health check (also wakes the server) ---------- */
app.get("/", (req, res) => res.json({ ok: true }));

/* ---------- Auth: verify the Supabase login token ---------- */
async function requireUser(req, res, next) {
  const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  if (!token) return res.status(401).json({ error: "Please sign in." });
  const { data, error } = await supabase.auth.getUser(token);
  if (error || !data.user) return res.status(401).json({ error: "Your session expired. Please sign in again." });
  req.user = data.user;
  next();
}

/* ---------- Auth routes (the page never talks to Supabase directly) ---------- */
const authLimit = rateLimit({ windowMs: 15 * 60 * 1000, max: 30, message: { error: "Too many attempts. Please wait a few minutes." } });
// A fresh client per request, so one person's login never leaks into the shared admin client.
const authClient = () =>
  createClient(SUPABASE_URL, process.env.SUPABASE_ANON_KEY || SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
const pack = (d) => ({
  session: d.session
    ? { access_token: d.session.access_token, refresh_token: d.session.refresh_token, expires_at: d.session.expires_at }
    : null,
  user: d.user ? { id: d.user.id, email: d.user.email } : null,
});
const validEmail = (e) => typeof e === "string" && /^\S+@\S+\.\S+$/.test(e) && e.length < 255;
const validPassword = (p) => typeof p === "string" && p.length >= 6 && p.length < 200;

app.post("/api/auth/signup", authLimit, async (req, res) => {
  const { email, password } = req.body || {};
  if (!validEmail(email) || !validPassword(password)) return res.status(400).json({ error: "Enter a valid email and a password of at least 6 characters." });
  const { data, error } = await authClient().auth.signUp({ email: email.trim(), password });
  if (error) return res.status(400).json({ error: error.message });
  res.json(pack(data));
});

app.post("/api/auth/login", authLimit, async (req, res) => {
  const { email, password } = req.body || {};
  if (!validEmail(email) || typeof password !== "string") return res.status(400).json({ error: "Enter your email and password." });
  const { data, error } = await authClient().auth.signInWithPassword({ email: email.trim(), password });
  if (error) return res.status(401).json({ error: error.message });
  res.json(pack(data));
});

app.post("/api/auth/refresh", async (req, res) => {
  const token = String((req.body && req.body.refresh_token) || "");
  if (!token) return res.status(400).json({ error: "Missing token." });
  const { data, error } = await authClient().auth.refreshSession({ refresh_token: token });
  if (error || !data.session) return res.status(401).json({ error: "Your session expired. Please sign in again." });
  res.json(pack(data));
});

app.post("/api/auth/forgot", authLimit, async (req, res) => {
  const { email, redirectTo } = req.body || {};
  if (validEmail(email)) {
    const target = typeof redirectTo === "string" && redirectTo.startsWith(ALLOWED_ORIGIN) ? redirectTo : undefined;
    await authClient().auth.resetPasswordForEmail(email.trim(), { redirectTo: target });
  }
  res.json({ ok: true }); // same reply either way, so emails can't be probed
});

app.post("/api/auth/reset", authLimit, async (req, res) => {
  const { access_token, password } = req.body || {};
  if (!validPassword(password)) return res.status(400).json({ error: "Use at least 6 characters." });
  const { data, error } = await supabase.auth.getUser(String(access_token || ""));
  if (error || !data.user) return res.status(401).json({ error: "This reset link has expired. Request a new one." });
  const { error: e2 } = await supabase.auth.admin.updateUserById(data.user.id, { password });
  if (e2) return res.status(400).json({ error: e2.message });
  res.json({ ok: true });
});

/* ---------- PayPal helpers ---------- */
let ppToken = { value: null, expires: 0 };

async function paypalToken() {
  if (ppToken.value && Date.now() < ppToken.expires) return ppToken.value;
  const basic = Buffer.from(PAYPAL_CLIENT_ID + ":" + PAYPAL_CLIENT_SECRET).toString("base64");
  const r = await fetch(PAYPAL_BASE + "/v1/oauth2/token", {
    method: "POST",
    headers: { Authorization: "Basic " + basic, "Content-Type": "application/x-www-form-urlencoded" },
    body: "grant_type=client_credentials",
  });
  if (!r.ok) throw new Error("PayPal auth failed (" + r.status + ")");
  const d = await r.json();
  ppToken = { value: d.access_token, expires: Date.now() + (d.expires_in - 60) * 1000 };
  return ppToken.value;
}

async function paypalSubscription(id) {
  const token = await paypalToken();
  const r = await fetch(PAYPAL_BASE + "/v1/billing/subscriptions/" + encodeURIComponent(id), {
    headers: { Authorization: "Bearer " + token },
  });
  if (r.status === 404) return null;
  if (!r.ok) throw new Error("PayPal lookup failed (" + r.status + ")");
  return r.json();
}

/* ---------- Subscription state in Supabase ---------- */
async function saveSubscription(userId, sub) {
  const row = {
    user_id: userId,
    paypal_subscription_id: sub.id,
    status: sub.status, // ACTIVE, APPROVAL_PENDING, SUSPENDED, CANCELLED, EXPIRED
    next_billing_time: (sub.billing_info && sub.billing_info.next_billing_time) || null,
    last_checked: new Date().toISOString(),
  };
  const { error } = await supabase.from(TABLE).upsert(row, { onConflict: "user_id" });
  if (error) throw new Error("Could not save subscription: " + error.message);
  return row;
}

// Returns { active, status, nextBillingTime }. Re-checks PayPal when the saved status is old.
async function getAccess(userId, { force = false } = {}) {
  const { data: row } = await supabase.from(TABLE).select("*").eq("user_id", userId).maybeSingle();
  if (!row) return { active: false, status: "NONE", nextBillingTime: null };

  let current = row;
  const stale = !row.last_checked || Date.now() - new Date(row.last_checked).getTime() > RECHECK_MS;
  if (force || stale) {
    const sub = await paypalSubscription(row.paypal_subscription_id);
    current = sub
      ? await saveSubscription(userId, sub)
      : { ...row, status: "CANCELLED" };
    if (!sub) await supabase.from(TABLE).update({ status: "CANCELLED", last_checked: new Date().toISOString() }).eq("user_id", userId);
  }
  return {
    active: current.status === "ACTIVE", // ACTIVE also covers the free trial period
    status: current.status,
    nextBillingTime: current.next_billing_time,
  };
}

async function requireSubscription(req, res, next) {
  try {
    const access = await getAccess(req.user.id);
    if (!access.active) return res.status(402).json({ error: "Start your free trial to use MyJarvis.", status: access.status });
    next();
  } catch (e) {
    console.error(e);
    res.status(502).json({ error: "Couldn’t verify your subscription. Please try again." });
  }
}

/* ---------- Routes: subscription ---------- */
// Called by the page right after PayPal approves the subscription.
app.post("/api/subscription/activate", requireUser, async (req, res) => {
  try {
    const id = String((req.body && req.body.subscriptionID) || "").trim();
    if (!id) return res.status(400).json({ error: "Missing subscription ID." });

    const sub = await paypalSubscription(id);
    if (!sub) return res.status(404).json({ error: "Subscription not found." });
    if (sub.plan_id !== PAYPAL_PLAN_ID) return res.status(400).json({ error: "Wrong plan." });
    if (sub.custom_id !== req.user.id) return res.status(403).json({ error: "This subscription belongs to another account." });
    if (sub.status !== "ACTIVE") return res.status(400).json({ error: "Subscription is not active yet (" + sub.status + ")." });

    const { data: taken } = await supabase
      .from(TABLE).select("user_id").eq("paypal_subscription_id", id).neq("user_id", req.user.id).maybeSingle();
    if (taken) return res.status(409).json({ error: "This subscription is already linked to another account." });

    const row = await saveSubscription(req.user.id, sub);
    res.json({ active: true, status: row.status, nextBillingTime: row.next_billing_time });
  } catch (e) {
    console.error(e);
    res.status(502).json({ error: "Couldn’t confirm your payment. Please try again." });
  }
});

// Called when the app opens and on the Account screen. Always asks PayPal.
app.get("/api/subscription/status", requireUser, async (req, res) => {
  try {
    res.json(await getAccess(req.user.id, { force: true }));
  } catch (e) {
    console.error(e);
    res.status(502).json({ error: "Couldn’t check your subscription." });
  }
});

// Optional: cancel from inside the app (otherwise link users to PayPal's manage page).
app.post("/api/subscription/cancel", requireUser, async (req, res) => {
  try {
    const { data: row } = await supabase.from(TABLE).select("*").eq("user_id", req.user.id).maybeSingle();
    if (!row) return res.status(404).json({ error: "No subscription found." });
    const token = await paypalToken();
    const r = await fetch(PAYPAL_BASE + "/v1/billing/subscriptions/" + encodeURIComponent(row.paypal_subscription_id) + "/cancel", {
      method: "POST",
      headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" },
      body: JSON.stringify({ reason: "Cancelled by user" }),
    });
    if (!r.ok && r.status !== 422) throw new Error("PayPal cancel failed (" + r.status + ")");
    res.json(await getAccess(req.user.id, { force: true }));
  } catch (e) {
    console.error(e);
    res.status(502).json({ error: "Couldn’t cancel right now. You can also cancel from your PayPal account." });
  }
});

/* ---------- Route: summarise (login + active subscription required) ---------- */
const perUser = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  keyGenerator: (req) => (req.user && req.user.id) || req.ip,
  message: { error: "Too many requests. Please wait a minute." },
});

const SYSTEM_PROMPT =
  "You turn study notes into a clear summary. Reply with ONLY valid JSON, no markdown, in this exact shape: " +
  '{"summary": string (3-5 sentences, plain English), "keywords": string[] (5-10), ' +
  '"definitions": [{"term": string, "definition": string}] (4-8, short and simple), ' +
  '"flashcards": [{"q": string, "a": string}] (4-8)}. ' +
  "Write in the same language as the notes.";

app.post("/api/summarise", requireUser, requireSubscription, perUser, async (req, res) => {
  const notes = String((req.body && req.body.notes) || "").trim();
  if (!notes) return res.status(400).json({ error: "Please add some notes first." });
  if (notes.length > MAX_NOTES) return res.status(400).json({ error: "Notes are too long. Keep them under " + MAX_NOTES.toLocaleString("en-US") + " characters." });

  try {
    const r = await fetch("https://api.groq.com/openai/v1/chat/completions", {
      method: "POST",
      headers: { Authorization: "Bearer " + GROQ_API_KEY, "Content-Type": "application/json" },
      body: JSON.stringify({
        model: GROQ_MODEL,
        temperature: 0.3,
        response_format: { type: "json_object" },
        messages: [
          { role: "system", content: SYSTEM_PROMPT },
          { role: "user", content: notes },
        ],
      }),
    });
    if (!r.ok) throw new Error("Groq replied " + r.status);
    const out = await r.json();
    const raw = (out.choices && out.choices[0] && out.choices[0].message.content) || "";
    const data = JSON.parse(raw.replace(/^```(?:json)?|```$/gm, "").trim());

    res.json({
      summary: String(data.summary || ""),
      keywords: Array.isArray(data.keywords) ? data.keywords.map(String) : [],
      definitions: Array.isArray(data.definitions) ? data.definitions : [],
      flashcards: Array.isArray(data.flashcards) ? data.flashcards : [],
    });
  } catch (e) {
    console.error(e);
    res.status(502).json({ error: "The summariser had a problem. Please try again." });
  }
});

app.listen(PORT, () => console.log("MyJarvis backend running on port " + PORT));
