#!/usr/bin/env node
// Sends one email with Nodemailer for the pqvpn portal (pqvpn/portal/mail.py).
//
// Input (stdin, JSON):  {"transport": <Nodemailer transport options>, "message": <Nodemailer message>}
// Output (stdout, JSON): {"messageId", "accepted", "rejected", "response"} (+ "message" for jsonTransport)
// Errors: exit code 1, one-line reason on stderr.  Credentials arrive on stdin only, never argv/env.
"use strict";

const nodemailer = require("nodemailer");

const TIMEOUTS = { connectionTimeout: 15000, greetingTimeout: 15000, socketTimeout: 30000 };

function readStdin() {
  return new Promise((resolve, reject) => {
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => {
      data += chunk;
      if (data.length > 1 << 20) reject(new Error("input too large"));
    });
    process.stdin.on("end", () => resolve(data));
    process.stdin.on("error", reject);
  });
}

async function main() {
  const { transport, message } = JSON.parse(await readStdin());
  if (!transport || !message || !message.to) throw new Error("transport and message.to are required");
  const options = transport.jsonTransport ? transport : { ...TIMEOUTS, ...transport };
  const transporter = nodemailer.createTransport(options);
  const info = await transporter.sendMail(message);
  const out = { messageId: info.messageId, accepted: info.accepted, rejected: info.rejected, response: info.response };
  if (transport.jsonTransport) out.message = info.message;
  process.stdout.write(JSON.stringify(out));
}

main().catch((err) => {
  process.stderr.write(String((err && err.message) || err).replace(/\s+/g, " ").trim());
  process.exitCode = 1;
});
