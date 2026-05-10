// k6 load test for the manager REST surface (M15.a).
//
// Usage:
//   k6 run --vus 10 --duration 30s tools/loadtest/rest.k6.js
//
// Reads:
//   BASE      manager REST URL (default http://localhost:8000)
//   EMAIL     admin email
//   PASSWORD  admin password
//
// Exits non-zero if p99 latency exceeds the M14.e SLO targets.

import http from "k6/http";
import { check, sleep } from "k6";
import { Trend, Rate } from "k6/metrics";

const BASE = __ENV.BASE || "http://localhost:8000";
const EMAIL = __ENV.EMAIL || "admin@example.local";
const PASSWORD = __ENV.PASSWORD || "change-me-please-12chars";

const latency = new Trend("rest_latency_ms", true);
const errors = new Rate("rest_errors");

export const options = {
  thresholds: {
    rest_latency_ms: ["p(99)<250"], // M14.e SLO: per-route p99 < 250ms
    rest_errors: ["rate<0.01"],     // <1% error rate
  },
  // Default vus / duration come from CLI; setting them here would
  // override `k6 run --vus N`.
};

let token = null;
function login() {
  const r = http.post(
    `${BASE}/api/auth/login`,
    JSON.stringify({ email: EMAIL, password: PASSWORD }),
    { headers: { "Content-Type": "application/json" } },
  );
  if (r.status !== 200) {
    console.error(`login failed ${r.status} ${r.body}`);
    return null;
  }
  return JSON.parse(r.body).access_token;
}

export function setup() {
  return { token: login() };
}

export default function (data) {
  if (!data.token) {
    errors.add(1);
    return;
  }
  const headers = { Authorization: `Bearer ${data.token}` };
  const endpoints = [
    "/api/me",
    "/api/hosts?limit=50",
    "/api/alerts?limit=50",
    "/api/commands?limit=50",
    "/api/host-groups?limit=50",
    "/api/rules?limit=50",
  ];
  const url = `${BASE}${endpoints[Math.floor(Math.random() * endpoints.length)]}`;
  const r = http.get(url, { headers });
  latency.add(r.timings.duration);
  errors.add(r.status >= 400 ? 1 : 0);
  check(r, { "status<400": (res) => res.status < 400 });
  sleep(0.1 + Math.random() * 0.2);
}
