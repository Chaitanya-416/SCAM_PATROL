import { createHash } from "node:crypto";
import type { RiskSignal, ScanInput, ScanKind, ScanResult } from "@workspace/api-zod";
import {
  getReputationSignal,
  hasIncidents,
  insertIncident,
} from "./scampatrol-db";
import { AIReviewError, reviewScanWithAI } from "./scampatrol-ai";

const URL_PATTERN = /(?:https?:\/\/|www\.)[^\s<>"']+/i;
const PHONE_PATTERN = /(?<!\w)\+?\d[\d\s().-]{7,}\d(?!\w)/;

function trimUrlPunctuation(value: string): string {
  return value.replace(/[),.!?;:]+$/, "");
}

function normalizePhone(value: string): string {
  const digits = value.replace(/\D/g, "");
  return `${value.trim().startsWith("+") ? "+" : ""}${digits}`;
}

function extractUrl(value: string): string | null {
  const match = value.match(URL_PATTERN);
  return match ? trimUrlPunctuation(match[0]) : null;
}

function extractPhone(value: string): string | null {
  const match = value.match(PHONE_PATTERN);
  return match?.[0] ?? null;
}

function normalizeUrl(value: string): { identifier: string; url: URL | null } {
  try {
    const candidate = /^https?:\/\//i.test(value) ? value : `https://${value}`;
    const url = new URL(candidate);
    return { identifier: url.hostname.toLowerCase(), url };
  } catch {
    return { identifier: value.toLowerCase().replace(/\/+$/, ""), url: null };
  }
}

function normalizedTarget(input: ScanInput): string {
  if (input.kind === "url") return normalizeUrl(input.input.trim()).identifier;
  if (input.kind === "phone" || input.kind === "call") {
    return normalizePhone(input.input);
  }
  const url = extractUrl(input.input);
  if (url) return normalizeUrl(url).identifier;
  const phone = extractPhone(input.input);
  if (phone) return normalizePhone(phone);
  const digest = createHash("sha256")
    .update(input.input.trim().toLowerCase())
    .digest("hex")
    .slice(0, 12);
  return `message:${digest}`;
}

function signal(
  signals: RiskSignal[],
  code: string,
  title: string,
  detail: string,
  points: number,
): void {
  if (signals.some((entry) => entry.code === code)) return;
  signals.push({ code, title, detail, points });
}

function inspectUrl(value: string, signals: RiskSignal[]): void {
  const { identifier: host, url } = normalizeUrl(value);
  if (!url) {
    signal(
      signals,
      "malformed-url",
      "Malformed web address",
      "The address could not be parsed as a normal web URL.",
      24,
    );
    return;
  }

  if (url.protocol !== "https:") {
    signal(
      signals,
      "unencrypted-url",
      "Unencrypted web address",
      "This link does not use HTTPS, so its connection is not encrypted.",
      8,
    );
  }
  if (url.username || url.password) {
    signal(
      signals,
      "embedded-credentials",
      "Hidden destination hint",
      "The address contains user information before the hostname, a common link-obfuscation trick.",
      28,
    );
  }
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host)) {
    signal(
      signals,
      "ip-host",
      "Direct IP address",
      "The link points to a raw IP address instead of a recognizable domain.",
      24,
    );
  }
  if (host.startsWith("xn--") || host.split(".").some((part) => part.startsWith("xn--"))) {
    signal(
      signals,
      "punycode-host",
      "Lookalike-domain encoding",
      "The domain uses punycode, which can disguise characters that resemble another brand.",
      26,
    );
  }
  if (
    /(^|\.)\b(?:bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly|rb\.gy|shorturl\.at)\b/i.test(
      host,
    )
  ) {
    signal(
      signals,
      "shortened-url",
      "Shortened link",
      "The final destination is hidden behind a URL-shortening service.",
      16,
    );
  }
  if (host.split(".")[0]?.split("-").length >= 4) {
    signal(
      signals,
      "hyphenated-domain",
      "Unusual domain name",
      "The hostname contains several hyphen-separated words, which can be used to imitate a trusted brand.",
      13,
    );
  }
  if (/(?:verify|login|signin|payment|fee|release|claim|re-auth)/i.test(url.pathname)) {
    signal(
      signals,
      "suspicious-url-path",
      "Payment or verification path",
      "The web address includes a payment, release, login, or verification path often used in scam lures.",
      14,
    );
  }
  const tld = host.split(".").at(-1)?.toLowerCase() ?? "";
  if (["click", "top", "work", "zip", "mov", "loan", "icu", "monster"].includes(tld)) {
    signal(
      signals,
      "uncommon-tld",
      "Uncommon domain ending",
      `The .${tld} ending is less common and is frequently used in low-trust campaigns.`,
      14,
    );
  }
}

function detectCategory(text: string, signals: RiskSignal[]): string {
  const lower = text.toLowerCase();
  const hasAny = (pattern: RegExp) => pattern.test(lower);
  if (hasAny(/courier|parcel|delivery|shipment|package|redelivery/)) {
    return "Delivery scam";
  }
  if (hasAny(/tech support|technical support|virus|remote access|device infected/)) {
    return "Tech support";
  }
  if (hasAny(/police|government|tax office|irs|customs|court|official department/)) {
    return "Authority impersonation";
  }
  if (hasAny(/bank|account|card|payment|refund|transfer|upi|wallet|crypto|tax/)) {
    return "Financial fraud";
  }
  if (
    signals.some((entry) =>
      ["credential-request", "one-time-code"].includes(entry.code),
    )
  ) {
    return "Credential phishing";
  }
  if (signals.some((entry) => entry.code.includes("url") || entry.code.endsWith("host"))) {
    return "Suspicious link";
  }
  if (signals.some((entry) => entry.code === "caller-impersonation")) {
    return "Impersonation";
  }
  return "Unclassified";
}

interface LocalAnalysis {
  target: string;
  riskScore: number;
  category: string;
  signals: RiskSignal[];
}

function analyzeLocally(input: ScanInput): LocalAnalysis {
  const target = normalizedTarget(input);
  const content = `${input.input} ${input.callerName ?? ""}`.trim();
  const signals: RiskSignal[] = [];

  if (
    /urgent|immediately|act now|expires?|final notice|last warning|within \d+ minutes|will be (?:closed|blocked|suspended)|today only/i.test(content) ||
    /(?:pay|verify|click|act|respond|reply|claim).{0,35}\btoday\b/i.test(content)
  ) {
    signal(
      signals,
      "urgency-pressure",
      "Pressure to act quickly",
      "The wording creates time pressure, a common tactic used to stop people from checking a request.",
      18,
    );
  }
  if (/password|passcode|credentials|log ?in|sign ?in|verify (?:your )?(?:account|identity)|account.{0,18}verify/i.test(content)) {
    signal(
      signals,
      "credential-request",
      "Account or password verification",
      "The message asks the recipient to verify an account or provide login information.",
      25,
    );
  }
  if (/\b(?:otp|one[- ]time password|verification code|security code)\b/i.test(content)) {
    signal(
      signals,
      "one-time-code",
      "One-time code requested",
      "A legitimate support agent should not ask you to share a one-time sign-in or bank code.",
      32,
    );
  }
  if (
    /send (?:money|payment)|pay (?:a )?(?:fee|fine|tax)|bank details|card details|cvv|gift card/i.test(content) ||
    /\b(?:pay|send|transfer|settle|remit)\b.{0,35}\b(?:fee|fine|tax|charge|payment|amount)\b/i.test(content) ||
    /\b(?:fee|fine|tax|charge|payment)\b.{0,35}\b(?:pay|send|transfer|settle|remit)\b/i.test(content)
  ) {
    signal(
      signals,
      "payment-request",
      "Unusual payment request",
      "The wording asks for money or sensitive payment details as part of the contact.",
      24,
    );
  }
  if (/police|government|tax office|irs|customs|court|fraud department|bank security|support desk|official department/i.test(content) && input.kind === "call") {
    signal(
      signals,
      "caller-impersonation",
      "Caller claims an official role",
      "The simulated caller identifies as a bank, support, or government authority; verify through a number you find independently.",
      23,
    );
  }
  if (input.kind === "call") {
    signal(
      signals,
      "simulated-incoming-call",
      "Simulated incoming call",
      "This is a demo call-screening decision; no real phone call was received or blocked.",
      8,
    );
  }

  const url = input.kind === "url" ? input.input.trim() : extractUrl(content);
  if (url) inspectUrl(url, signals);

  const phone = input.kind === "phone" || input.kind === "call"
    ? normalizePhone(input.input)
    : extractPhone(content);
  if (phone) {
    const digits = phone.replace(/\D/g, "");
    if (/(\d)\1{4,}/.test(digits)) {
      signal(
        signals,
        "repeated-number-pattern",
        "Repeated digit pattern",
        "The number contains an unusually long repeated-digit sequence.",
        18,
      );
    }
  }

  const reputation = getReputationSignal(input.kind, target);
  if (reputation.riskBoost > 0) {
    signal(
      signals,
      "community-reports",
      "Previously reported target",
      `This target has ${reputation.reportCount} saved community report${reputation.reportCount === 1 ? "" : "s"}; its reputation adds ${reputation.riskBoost} risk points.`,
      reputation.riskBoost,
    );
  }

  const rawScore = signals.reduce((sum, entry) => sum + entry.points, 0);
  const riskScore = Math.min(100, rawScore);
  if (signals.length === 0) {
    signal(
      signals,
      "no-known-signals",
      "No strong scam signals found",
      "This check did not find the patterns covered by the demo rules. A low score is not proof that a sender is safe.",
      0,
    );
  }

  return {
    target,
    riskScore,
    category: detectCategory(content, signals),
    signals,
  };
}

function recommendationFor(input: ScanInput, riskScore: number): string {
  return riskScore >= 70
    ? input.kind === "call"
      ? "Blocked in this simulation. Do not share codes or call back; contact the organization using its official number."
      : "Do not open the link, reply, or share information. Verify the request through an official channel."
    : riskScore >= 40
      ? "Pause and verify the sender independently before replying, paying, or opening links."
      : "No strong warning signs were found. Still verify unexpected requests using a trusted channel.";
}

function finishAnalysis(
  input: ScanInput,
  analysis: LocalAnalysis,
  signals: RiskSignal[],
  riskScore: number,
  category: string,
): ScanResult {
  const decision: ScanResult["decision"] =
    riskScore >= 70 ? "block" : riskScore >= 40 ? "caution" : "allow";
  const isBlocked = input.kind === "call" && riskScore >= 70;
  const status: ScanResult["status"] = isBlocked
    ? "blocked"
    : riskScore >= 40
      ? "caution"
      : "safe";
  return insertIncident(input, {
    target: analysis.target,
    riskScore,
    category,
    recommendation: recommendationFor(input, riskScore),
    decision,
    status,
    isBlocked,
    signals,
  });
}

export async function analyzeScan(input: ScanInput): Promise<ScanResult> {
  const local = analyzeLocally(input);
  let signals: RiskSignal[];
  let riskScore: number;
  let category: string;
  try {
    const aiReview = await reviewScanWithAI(input);
    const aiDetail = aiReview.reasons.length
      ? aiReview.reasons.join(" ")
      : "No additional contextual risk beyond the local signal checks was identified.";
    signals = [
      ...local.signals,
      {
        code: "ai-context-review",
        title: "AI context review",
        detail: aiDetail,
        points: aiReview.additionalRiskPoints,
      },
    ];
    riskScore = Math.min(100, local.riskScore + aiReview.additionalRiskPoints);
    category =
      aiReview.category !== "Unclassified" ? aiReview.category : local.category;
  } catch (error) {
    if (!(error instanceof AIReviewError)) throw error;
    console.warn(
      "ScamPatrol AI review unavailable; saving an explicitly local-only assessment.",
    );
    signals = [
      ...local.signals,
      {
        code: "ai-review-unavailable",
        title: "AI review unavailable",
        detail:
          "OpenAI did not return a review. This saved score uses local signal checks and target reputation only.",
        points: 0,
      },
    ];
    riskScore = local.riskScore;
    category = local.category;
  }
  return finishAnalysis(input, local, signals, riskScore, category);
}

export function seedDemoIncidents(): void {
  if (hasIncidents()) return;
  const samples: ScanInput[] = [
    {
      kind: "message",
      input:
        "URGENT: Your bank account is suspended. Verify your password and share the OTP now: http://secure-bank-login.example/verify",
    },
    {
      kind: "url",
      input: "http://courier-redelivery.example/parcel-fee",
    },
    {
      kind: "call",
      input: "+91 90000 12345",
      callerName: "Bank security desk: urgent OTP verification required immediately",
    },
  ];
  for (const sample of samples) {
    const local = analyzeLocally(sample);
    finishAnalysis(sample, local, local.signals, local.riskScore, local.category);
  }
}
