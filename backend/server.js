// server.js
const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const axios = require("axios");
const nodemailer = require("nodemailer");
const os = require("os");

function getServerIP() {
    const interfaces = os.networkInterfaces();
    for (const name of Object.keys(interfaces)) {
        for (const iface of interfaces[name]) {
            if (iface.family === "IPv4" && !iface.internal) {
                return iface.address;
            }
        }
    }
    return "localhost";
}

const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: "keerthanam451@gmail.com",
        pass: "ydojachhjtfwjbjt"
    }
});

function sendEmailAlert(subject, message, email = null, isLoginAlert = false, alertToken = null) {
    const encodedEmail = email ? encodeURIComponent(email) : null;
    const serverIP = getServerIP();
    const tokenSuffix = alertToken ? `?token=${alertToken}` : "";

    let htmlContent = `
        <div style="font-family:monospace;background:#07080f;color:#e0e6ff;
                    padding:30px;border-radius:10px;max-width:500px;">
            <h2 style="color:#ff4d6d;">🚨 SENTINEL SECURITY ALERT</h2>
            <hr style="border-color:#7b8cde33;"/>
            <pre style="color:#e0e6ff;white-space:pre-wrap;">${message}</pre>
    `;

    if (email && !isLoginAlert) {
        htmlContent += `
            <hr style="border-color:#7b8cde33;"/>
            <p style="color:#ff9f43;font-size:14px;">⚠️ Was this activity done by you?</p>
            <table style="margin-top:16px;border-collapse:separate;border-spacing:10px;">
                <tr>
                    <td>
                        <a href="http://${serverIP}:3000/api/confirm/${encodedEmail}${tokenSuffix}"
                           style="display:block;background:#00e5a0;color:#07080f;
                                  padding:14px 28px;border-radius:8px;
                                  text-decoration:none;font-weight:bold;
                                  font-family:Arial,sans-serif;font-size:14px;text-align:center;">
                            ✅ YES, This was me
                        </a>
                    </td>
                    <td>
                        <a href="http://${serverIP}:3000/api/block/${encodedEmail}${tokenSuffix}"
                           style="display:block;background:#ff4d6d;color:#ffffff;
                                  padding:14px 28px;border-radius:8px;
                                  text-decoration:none;font-weight:bold;
                                  font-family:Arial,sans-serif;font-size:14px;text-align:center;">
                            ❌ NO, Block session
                        </a>
                    </td>
                </tr>
            </table>
            <p style="color:#4a5080;font-size:11px;margin-top:16px;">
                If you click NO, the session will be immediately blocked.
            </p>
        `;
    }

    if (email && isLoginAlert) {
        htmlContent += `
            <hr style="border-color:#7b8cde33;"/>
            <p style="color:#ff9f43;font-size:14px;">⚠️ Was this you trying to login?</p>
            <table style="margin-top:16px;border-collapse:separate;border-spacing:10px;">
                <tr>
                    <td>
                        <a href="http://${serverIP}:3000/api/unlock/${encodedEmail}"
                           style="display:block;background:#00e5a0;color:#07080f;
                                  padding:14px 28px;border-radius:8px;
                                  text-decoration:none;font-weight:bold;
                                  font-family:Arial,sans-serif;font-size:14px;text-align:center;">
                            ✅ YES, Unlock my account
                        </a>
                    </td>
                    <td>
                        <a href="http://${serverIP}:3000/api/block-login/${encodedEmail}"
                           style="display:block;background:#ff4d6d;color:#ffffff;
                                  padding:14px 28px;border-radius:8px;
                                  text-decoration:none;font-weight:bold;
                                  font-family:Arial,sans-serif;font-size:14px;text-align:center;">
                            ❌ NO, Keep blocked
                        </a>
                    </td>
                </tr>
            </table>
            <p style="color:#4a5080;font-size:11px;margin-top:16px;">
                If you did not attempt this login, click NO to keep your account blocked.
            </p>
        `;
    }

    htmlContent += `</div>`;

    const mailOptions = {
        from: "keerthanam451@gmail.com",
        to: "keerthanam451@gmail.com",
        subject: subject,
        html: htmlContent
    };

    transporter.sendMail(mailOptions, (err, info) => {
        if (err) console.log("[!] Email error:", err);
        else console.log("[✓] Alert email sent!");
    });
}

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "../frontend")));

// ── Config ────────────────────────────────────────────────────
const PORT          = 3000;
const AI_URL        = "http://localhost:5001";
const LOG_FILE      = path.join(__dirname, "logs.json");
const MAX_FAILED    = 5;
const COOLDOWN_AFTER = 3;
const SESSION_TIMEOUT = 15 * 60 * 1000;
const packetLog     = [];

function getPacketSize(req) {
    const bodySize   = JSON.stringify(req.body || {}).length;
    const headerSize = JSON.stringify(req.headers || {}).length;
    return bodySize + headerSize;
}

async function getGeoLocation(ip) {
    try {
        if (ip === "127.0.0.1" || ip === "::1" ||
            ip.startsWith("192.168") || ip.startsWith("10.")) {
            return { city: "Local Network", country: "Local", countryCode: "LO", isp: "Local ISP" };
        }
        const res = await axios.get(`http://ip-api.com/json/${ip}`, { timeout: 2000 });
        return {
            city:        res.data.city        || "Unknown",
            country:     res.data.country     || "Unknown",
            countryCode: res.data.countryCode || "??",
            isp:         res.data.isp         || "Unknown"
        };
    } catch (e) {
        return { city: "Unknown", country: "Unknown", countryCode: "??", isp: "Unknown" };
    }
}

async function logPacket(req, eventType, status, isAttacker = false) {
    const realIP  = req.ip || req.connection.remoteAddress || "127.0.0.1";
    const cleanIP = realIP.replace("::ffff:", "") || "127.0.0.1";

    const attackerIPv6 = () => {
        const groups = [];
        for (let i = 0; i < 8; i++) {
            groups.push(Math.floor(Math.random() * 65535).toString(16).padStart(4, "0"));
        }
        return groups.join(":");
    };

    const srcIP = isAttacker ? attackerIPv6() :
        (cleanIP === "::1" ? "192.168.1." + Math.floor(Math.random() * 50 + 100) : cleanIP);

    const geo = await getGeoLocation(isAttacker ? "45.33.32.156" : cleanIP);

    const packet = {
        id:          Date.now(),
        timestamp:   new Date().toISOString(),
        src_ip:      srcIP,
        dst_ip:      "192.168.1.100",
        protocol:    req.secure ? "HTTPS" : "HTTP",
        port:        3000,
        size:        getPacketSize(req) + Math.floor(Math.random() * 200),
        event:       eventType,
        status:      status,
        is_ipv6:     isAttacker,
        city:        geo.city,
        country:     geo.country,
        countryCode: geo.countryCode,
        isp:         geo.isp
    };
    packetLog.unshift(packet);
    if (packetLog.length > 200) packetLog.pop();
    return packet;
}

// ── Dummy Users Database ──────────────────────────────────────
const USERS = {
    "keerthana@dbit.com": { password: "keer123", role: "admin", name: "Keerthana" },
    "koushalya@dbit.com": { password: "kous456", role: "user",  name: "Koushalya" },
    "hacker@evil.com":    { password: "hack789", role: "user",  name: "Hacker"    },
};

// ── In-memory stores ──────────────────────────────────────────
const failedAttempts = {};
const lockedEmails   = {};
const activeSessions = {};
const activityLog    = [];
const pendingAlerts  = {};

// ── Dynamic Policy Store ──────────────────────────────────────
const attackHistory  = {};

function getDynamicPolicy(email) {
    const history = attackHistory[email];
    if (!history) return { level: "normal", timeoutMs: 5 * 60 * 1000, requireEmail: true };
    if (history.count >= 3) return { level: "permanent", timeoutMs: 0, requireEmail: false };
    if (history.count === 2) return { level: "strict",   timeoutMs: 2 * 60 * 1000, requireEmail: true };
    return { level: "normal", timeoutMs: 5 * 60 * 1000, requireEmail: true };
}

function recordAttack(email) {
    if (!attackHistory[email]) {
        attackHistory[email] = { count: 0, lastAttack: null, policy: "normal" };
    }
    attackHistory[email].count      += 1;
    attackHistory[email].lastAttack  = Date.now();
    if (attackHistory[email].count >= 3)      attackHistory[email].policy = "permanent";
    else if (attackHistory[email].count === 2) attackHistory[email].policy = "strict";
    else                                       attackHistory[email].policy = "normal";
    console.log(`[POLICY] ${email} → attack #${attackHistory[email].count} → policy: ${attackHistory[email].policy}`);
    return attackHistory[email];
}

// ── Helper: Save log ──────────────────────────────────────────
function saveLog(entry) {
    entry.timestamp = new Date().toISOString();
    activityLog.unshift(entry);
    if (activityLog.length > 200) activityLog.pop();
    let logs = [];
    if (fs.existsSync(LOG_FILE)) {
        try { logs = JSON.parse(fs.readFileSync(LOG_FILE, "utf8")); } catch { }
    }
    logs.unshift(entry);
    if (logs.length > 500) logs = logs.slice(0, 500);
    fs.writeFileSync(LOG_FILE, JSON.stringify(logs, null, 2));
    console.log(`[LOG] ${entry.event} | user=${entry.user || "?"} | result=${entry.result || ""}`);
}

// ── Helper: Parse AI response ─────────────────────────────────
// Extracts all new fields from Flask response safely
function parseAIResponse(data) {
    return {
        result:           data.result           || "NORMAL",
        risk_score:       data.risk_score        || 0,
        risk_level:       data.risk_level        || "LOW",
        raw_score:        data.raw_score         || 0,
        threat_label:     data.threat_label      || "No Threat Detected",
        shap_explanation: data.shap_explanation  || [],
        models: {
            isolation_forest: data.models?.isolation_forest || "NORMAL",
            one_class_svm:    data.models?.one_class_svm    || "NORMAL",
            lof:              data.models?.lof               || "NORMAL",
            anomaly_votes:    data.models?.anomaly_votes     || 0
        }
    };
}

// ── Route: Login ──────────────────────────────────────────────
app.post("/api/login", async (req, res) => {
    const { email, password } = req.body;
    const ip        = req.ip || "unknown";
    const loginHour = new Date().getHours();

    logPacket(req, "LOGIN_REQUEST", "RECEIVED", false);

    function isMaliciousInput(input) {
        const sqlPattern = /(\bSELECT\b|\bDROP\b|\bINSERT\b|\bUNION\b|--|;|')/i;
        const xssPattern = /<script|javascript:|on\w+=/i;
        return sqlPattern.test(input) || xssPattern.test(input);
    }

    if (isMaliciousInput(email) || isMaliciousInput(password)) {
        saveLog({
            event: "MALICIOUS_INPUT", user: email, ip,
            result: "BLOCKED", reason: "SQL Injection or XSS attempt",
            risk_score: 100, risk_level: "CRITICAL",
            threat_label: "Malicious Input Attack"
        });
        return res.status(400).json({
            success: false,
            message: "🚨 Malicious input detected! Request blocked.",
            risk_score: 100
        });
    }

    if (lockedEmails[email]) {
        saveLog({
            event: "LOGIN_LOCKED", user: email, ip,
            result: "BLOCKED", reason: "Account locked after too many attempts",
            risk_score: 100, risk_level: "CRITICAL",
            threat_label: "Account Locked"
        });
        return res.status(429).json({
            success: false,
            message: "🔒 Account locked! Check your email to unlock.",
            risk_score: 100, locked: true
        });
    }

    const fails = failedAttempts[ip] || 0;
    if (fails >= MAX_FAILED) {
        logPacket(req, "LOGIN_BLOCKED", "BLOCKED", true);
        saveLog({
            event: "LOGIN_BLOCKED", user: email, ip,
            result: "BLOCKED", reason: "Too many failed attempts",
            risk_score: 100, risk_level: "CRITICAL",
            threat_label: "Suspected Brute Force Attack"
        });
        return res.status(429).json({
            success: false,
            message: "⛔ IP Blocked! Too many failed attempts.",
            risk_score: 100, permanent: true
        });
    }

    const user = USERS[email];
    if (!user || user.password !== password) {
        failedAttempts[ip] = (failedAttempts[ip] || 0) + 1;
        const currentFails  = failedAttempts[ip];

        logPacket(req, "LOGIN_FAILED", "DROPPED", true);
        saveLog({
            event: "LOGIN_FAILED", user: email, ip,
            result: "FAILED", failCount: currentFails,
            risk_score: 50, risk_level: "MEDIUM",
            threat_label: currentFails >= 3 ? "Suspected Brute Force Attack" : "Failed Login Attempt"
        });

        if (currentFails === MAX_FAILED - 1) {
            return res.status(401).json({
                success: false,
                message: "⚠️ Last attempt! Next failure will lock your account.",
                failCount: currentFails, lastAttempt: true
            });
        }

        if (currentFails >= MAX_FAILED) {
            lockedEmails[email] = true;
            sendEmailAlert(
                "🔒 SENTINEL — Account Locked!",
                `Your account has been locked due to too many failed login attempts.

Email: ${email}
IP Address: ${ip}
Time: ${new Date().toISOString()}
Failed Attempts: ${currentFails}

If this was you, click the button below to unlock your account.
If this was NOT you, keep it blocked!`,
                email, true
            );
            saveLog({
                event: "ACCOUNT_LOCKED", user: email, ip,
                result: "BLOCKED", risk_score: 100,
                risk_level: "CRITICAL",
                threat_label: "Suspected Brute Force Attack"
            });
            return res.status(429).json({
                success: false,
                message: "🔒 Account locked! Check your email to unlock.",
                risk_score: 100, locked: true, emailSent: true
            });
        }

        return res.status(401).json({
            success: false,
            message: `❌ Invalid email or password! (${currentFails}/${MAX_FAILED} attempts)`,
            failCount: currentFails
        });
    }

    // ── AI Check on Login ─────────────────────────────────────
    let ai = { result: "NORMAL", risk_score: 0, risk_level: "LOW", threat_label: "Normal Login", shap_explanation: [], models: {} };
    try {
        const aiResponse = await axios.post(`${AI_URL}/predict/login`, {
            login_hour:      loginHour,
            failed_attempts: fails,
            request_count:   10
        });
        ai = parseAIResponse(aiResponse.data);
    } catch (err) {
        console.warn("[!] AI module unreachable, defaulting to NORMAL");
    }

    if (ai.result === "ANOMALY") {
        logPacket(req, "AI_BLOCKED", "BLOCKED", true);
        saveLog({
            event:            "LOGIN_ANOMALY",
            user:             email,
            ip,
            result:           "BLOCKED",
            risk_score:       ai.risk_score,
            risk_level:       ai.risk_level,
            threat_label:     ai.threat_label,
            shap_explanation: ai.shap_explanation,
            models:           ai.models,
            loginHour
        });
        return res.status(403).json({
            success: false,
            message: "🤖 AI detected suspicious behavior! Login blocked.",
            aiResult:     ai.result,
            risk_score:   ai.risk_score,
            risk_level:   ai.risk_level,
            threat_label: ai.threat_label
        });
    }

    failedAttempts[ip] = 0;
    activeSessions[email] = {
        loginTime:    Date.now(),
        loginHour,
        requestCount: 0,
        role:         user.role,
        name:         user.name,
        ip,
        lastActivity: Date.now()
    };

    logPacket(req, "LOGIN_SUCCESS", "ALLOWED", false);
    saveLog({
        event:            "LOGIN_SUCCESS",
        user:             email,
        ip,
        result:           "ALLOWED",
        role:             user.role,
        risk_score:       ai.risk_score,
        risk_level:       ai.risk_level,
        threat_label:     ai.threat_label,
        shap_explanation: ai.shap_explanation,
        models:           ai.models
    });

    return res.json({
        success:      true,
        message:      "✅ Login successful!",
        user:         { email, role: user.role, name: user.name },
        aiResult:     ai.result,
        risk_score:   ai.risk_score,
        risk_level:   ai.risk_level,
        threat_label: ai.threat_label
    });
});

// ── Route: Unlock account ─────────────────────────────────────
app.get("/api/unlock/:email", (req, res) => {
    const email = decodeURIComponent(req.params.email);
    delete lockedEmails[email];
    Object.keys(failedAttempts).forEach(k => { failedAttempts[k] = 0; });
    saveLog({ event: "ACCOUNT_UNLOCKED", user: email, result: "UNLOCKED" });
    res.send(`
        <html><body style="background:#07080f;color:#00e5a0;font-family:monospace;
                           display:flex;align-items:center;justify-content:center;
                           height:100vh;text-align:center;">
            <div>
                <h1>✅ Account Unlocked!</h1>
                <p style="color:#7b8cde;margin-top:10px;">Your account has been unlocked. You may login again.</p>
                <a href="http://${getServerIP()}:3000"
                   style="display:inline-block;margin-top:20px;padding:12px 24px;
                          background:#00e5a0;color:#07080f;border-radius:8px;
                          text-decoration:none;font-weight:bold;">
                    Go to Login
                </a>
            </div>
        </body></html>
    `);
});

// ── Route: Keep blocked ───────────────────────────────────────
app.get("/api/block-login/:email", (req, res) => {
    const email = decodeURIComponent(req.params.email);
    lockedEmails[email] = true;
    saveLog({ event: "ACCOUNT_KEPT_BLOCKED", user: email, result: "BLOCKED" });
    res.send(`
        <html><body style="background:#07080f;color:#ff4d6d;font-family:monospace;
                           display:flex;align-items:center;justify-content:center;
                           height:100vh;text-align:center;">
            <div>
                <h1>🔒 Account Kept Blocked!</h1>
                <p style="color:#7b8cde;margin-top:10px;">Your account remains blocked for security.</p>
            </div>
        </body></html>
    `);
});

// ── Route: Track user activity ────────────────────────────────
app.post("/api/activity", async (req, res) => {
    const { email, action } = req.body;
    const session = activeSessions[email];

    if (!session) {
        return res.status(401).json({ success: false, message: "Not logged in" });
    }

    if (session.frozen) {
        return res.status(403).json({
            success: false,
            message: "⏳ Session frozen! Waiting for your email verification.",
            frozen: true
        });
    }

    if (!session && pendingAlerts[email] === "blocked") {
        return res.status(403).json({ success: false, message: "🚫 Permanently blocked!", permanent: true });
    }

    const now = Date.now();
    if (now - session.lastActivity > SESSION_TIMEOUT) {
        delete activeSessions[email];
        saveLog({ event: "SESSION_TIMEOUT", user: email, result: "TIMEOUT" });
        return res.status(401).json({
            success: false,
            message: "⏱ Session timed out! Please login again.",
            timeout: true
        });
    }

    session.requestCount += 1;
    session.lastActivity  = now;

    // ── AI Check on Activity ──────────────────────────────────
    let ai = { result: "NORMAL", risk_score: 0, risk_level: "LOW", threat_label: "Normal Activity", shap_explanation: [], models: {} };
    try {
        const aiResponse = await axios.post(`${AI_URL}/predict/activity`, {
            login_hour:      session.loginHour,
            failed_attempts: 0,
            request_count:   session.requestCount
        });
        ai = parseAIResponse(aiResponse.data);
    } catch (err) {
        console.warn("[!] AI module unreachable");
    }

    const finalRiskScore = ai.result === "ANOMALY" ? ai.risk_score :
        session.requestCount > 20 ? 85 :
        session.requestCount > 15 ? 70 :
        session.requestCount > 10 ? 55 :
        session.requestCount > 5  ? 30 : ai.risk_score;

    // Recalculate risk level from final score
    const finalRiskLevel =
        finalRiskScore >= 81 ? "CRITICAL" :
        finalRiskScore >= 61 ? "HIGH" :
        finalRiskScore >= 31 ? "MEDIUM" : "LOW";

    saveLog({
        event:            "ACTIVITY",
        user:             email,
        action,
        requestCount:     session.requestCount,
        result:           ai.result,
        risk_score:       finalRiskScore,
        risk_level:       finalRiskLevel,
        threat_label:     ai.threat_label,
        shap_explanation: ai.shap_explanation,
        models:           ai.models
    });

    // ── Dynamic Policy Enforcement ────────────────────────────
    const shouldTrigger = !session.emailSent &&
        session.requestCount > 5 &&
        (ai.result === "ANOMALY" || session.requestCount > 10);

    if (shouldTrigger) {
        const history = recordAttack(email);
        const policy  = getDynamicPolicy(email);

        saveLog({
            event:        "POLICY_ENFORCED",
            user:         email,
            result:       "BLOCKED",
            reason:       `Dynamic policy applied — attack #${history.count} — level: ${policy.level}`,
            risk_score:   finalRiskScore,
            risk_level:   finalRiskLevel,
            threat_label: ai.threat_label,
            policyLevel:  policy.level,
            attackCount:  history.count
        });

        // 🔴 3rd+ attack → PERMANENT BLOCK
        if (policy.level === "permanent") {
            delete activeSessions[email];
            console.log(`[🚫] PERMANENT BLOCK: ${email} — repeated anomaly (attack #${history.count})`);
            return res.status(403).json({
                success:      false,
                message:      "🚫 Permanently blocked! Repeated suspicious activity detected. Contact admin.",
                risk_score:   100,
                risk_level:   "CRITICAL",
                threat_label: ai.threat_label,
                permanent:    true,
                policyLevel:  "permanent",
                attackCount:  history.count
            });
        }

        const alertToken    = Date.now().toString(36) + Math.random().toString(36).substr(2, 5);
        session.alertToken  = alertToken;

        // 🟠 2nd attack → STRICT policy
        if (policy.level === "strict") {
            sendEmailAlert(
                "🚨 SENTINEL ALERT — REPEATED Suspicious Activity! (STRICT POLICY)",
                `User: ${email}
Risk Score: ${finalRiskScore}/100
Risk Level: ${finalRiskLevel}
Threat: ${ai.threat_label}
Action: ${action}
Requests: ${session.requestCount}
Time: ${new Date().toISOString()}
Attack Count: ${history.count} (REPEATED OFFENSE)
Alert Token: ${alertToken}

⚠️ STRICT POLICY APPLIED — You have 2 minutes to respond!
Failure to respond will result in PERMANENT block.`,
                email, false, alertToken
            );
            session.emailSent = true;
            session.frozen    = true;
            pendingAlerts[email] = alertToken;

            setTimeout(() => {
                if (pendingAlerts[email] === alertToken) {
                    delete activeSessions[email];
                    pendingAlerts[email] = "timeout";
                    saveLog({
                        event:       "AUTO_BLOCK_STRICT_POLICY",
                        user:        email,
                        result:      "BLOCKED",
                        reason:      "Strict policy — no response within 2 minutes",
                        policyLevel: "strict"
                    });
                    console.log(`[⚠️] STRICT AUTO-BLOCK: ${email} — no response in 2 mins`);
                }
            }, 2 * 60 * 1000);

            return res.json({
                success:      false,
                frozen:       true,
                action,
                requestCount: session.requestCount,
                aiResult:     ai.result,
                risk_score:   finalRiskScore,
                risk_level:   finalRiskLevel,
                threat_label: ai.threat_label,
                alert:        "⚠️ STRICT POLICY: Session frozen! Check your email within 2 minutes!",
                policyLevel:  "strict",
                attackCount:  history.count
            });
        }

        // 🟡 1st attack → NORMAL policy
        sendEmailAlert(
            "🚨 SENTINEL ALERT — Suspicious Activity Detected!",
            `User: ${email}
Risk Score: ${finalRiskScore}/100
Risk Level: ${finalRiskLevel}
Threat: ${ai.threat_label}
Action: ${action}
Requests: ${session.requestCount}
Time: ${new Date().toISOString()}
Alert Token: ${alertToken}

Suspicious rapid requests detected in active session!
Was this you?`,
            email, false, alertToken
        );
        session.emailSent    = true;
        session.frozen       = true;
        pendingAlerts[email] = alertToken;

        setTimeout(() => {
            if (pendingAlerts[email] === alertToken) {
                delete activeSessions[email];
                pendingAlerts[email] = "timeout";
                saveLog({
                    event:       "AUTO_BLOCK_NO_RESPONSE",
                    user:        email,
                    result:      "BLOCKED",
                    reason:      "No response within 5 minutes",
                    policyLevel: "normal"
                });
                console.log(`[⚠️] AUTO-BLOCK: ${email} — no response in 5 mins`);
            }
        }, 5 * 60 * 1000);

        return res.json({
            success:      false,
            frozen:       true,
            action,
            requestCount: session.requestCount,
            aiResult:     ai.result,
            risk_score:   finalRiskScore,
            risk_level:   finalRiskLevel,
            threat_label: ai.threat_label,
            alert:        "⚠️ Session frozen! Check your email to verify identity.",
            policyLevel:  "normal"
        });
    }

    return res.json({
        success:      true,
        action,
        requestCount: session.requestCount,
        aiResult:     ai.result,
        risk_score:   finalRiskScore,
        risk_level:   finalRiskLevel,
        threat_label: ai.threat_label,
        alert:        ai.result === "ANOMALY" ? "⚠️ Abnormal activity detected!" : null,
        policyLevel:  attackHistory[email]?.policy || "normal"
    });
});

// ── Route: Logout ─────────────────────────────────────────────
app.post("/api/logout", (req, res) => {
    const { email } = req.body;
    delete activeSessions[email];
    saveLog({ event: "LOGOUT", user: email, result: "LOGGED_OUT" });
    res.json({ success: true, message: "Logged out successfully" });
});

// ── Route: Get logs ───────────────────────────────────────────
app.get("/api/logs", (req, res) => {
    res.json(activityLog.slice(0, 100));
});

// ── Route: Get packets ────────────────────────────────────────
app.get("/api/packets", (req, res) => {
    res.json(packetLog.slice(0, 100));
});

// ── Route: Get stats ──────────────────────────────────────────
app.get("/api/stats", (req, res) => {
    res.json({
        totalEvents:    activityLog.length,
        activeSessions: Object.keys(activeSessions).length,
        loginSuccess:   activityLog.filter(e => e.event === "LOGIN_SUCCESS").length,
        loginFailed:    activityLog.filter(e => e.event === "LOGIN_FAILED").length,
        anomalies:      activityLog.filter(e => e.result === "ANOMALY" || e.event === "LOGIN_ANOMALY").length,
        blocked:        activityLog.filter(e => e.result === "BLOCKED").length,
    });
});

// ── Route: Get policy status for a user ──────────────────────
app.get("/api/policy/:email", (req, res) => {
    const email   = decodeURIComponent(req.params.email);
    const history = attackHistory[email];
    const policy  = getDynamicPolicy(email);
    res.json({
        email,
        attackCount:   history?.count  || 0,
        lastAttack:    history?.lastAttack || null,
        currentPolicy: policy.level,
        timeoutMs:     policy.timeoutMs,
        requireEmail:  policy.requireEmail,
        locked:        !!lockedEmails[email]
    });
});

// ── Route: Confirm session (user says YES) ────────────────────
app.get("/api/confirm/:email", (req, res) => {
    const email   = decodeURIComponent(req.params.email);
    const token   = req.query.token || null;
    const session = activeSessions[email];

    if (token && pendingAlerts[email] !== token) {
        return res.send(`
            <html><body style="background:#07080f;color:#ff9f43;font-family:monospace;
                               display:flex;align-items:center;justify-content:center;
                               height:100vh;text-align:center;">
                <div>
                    <h1>⏰ Link Expired!</h1>
                    <p style="color:#7b8cde;margin-top:10px;">This email link has already expired.<br/>A newer security event has been issued.</p>
                </div>
            </body></html>
        `);
    }

    if (session) {
        session.confirmed    = true;
        session.frozen       = false;
        session.emailSent    = false;
        session.requestCount = 0;
        session.alertToken   = null;
        pendingAlerts[email] = "confirmed";
        saveLog({ event: "SESSION_CONFIRMED", user: email, result: "CONFIRMED" });
        res.send(`
            <html><body style="background:#07080f;color:#00e5a0;font-family:monospace;
                               display:flex;align-items:center;justify-content:center;
                               height:100vh;text-align:center;">
                <div>
                    <h1>✅ Session Confirmed!</h1>
                    <p style="color:#7b8cde;margin-top:10px;">Your session has been verified. You may continue.</p>
                </div>
            </body></html>
        `);
    } else {
        res.send(`
            <html><body style="background:#07080f;color:#ff4d6d;font-family:monospace;
                               display:flex;align-items:center;justify-content:center;
                               height:100vh;text-align:center;">
                <div>
                    <h1>❌ Session Expired!</h1>
                    <p style="color:#7b8cde;margin-top:10px;">Session not found or already expired.</p>
                </div>
            </body></html>
        `);
    }
});

// ── Route: Block session (user says NO) ───────────────────────
app.get("/api/block/:email", (req, res) => {
    const email = decodeURIComponent(req.params.email);
    const token = req.query.token || null;

    if (token && pendingAlerts[email] !== token) {
        return res.send(`
            <html><body style="background:#07080f;color:#ff9f43;font-family:monospace;
                               display:flex;align-items:center;justify-content:center;
                               height:100vh;text-align:center;">
                <div>
                    <h1>⏰ Link Expired!</h1>
                    <p style="color:#7b8cde;margin-top:10px;">This email link has already expired.<br/>A newer security event has been issued.</p>
                </div>
            </body></html>
        `);
    }

    if (activeSessions[email]) {
        delete activeSessions[email];
        pendingAlerts[email] = "blocked";
        saveLog({ event: "SESSION_BLOCKED_BY_USER", user: email, result: "BLOCKED" });
    }
    res.send(`
        <html><body style="background:#07080f;color:#ff4d6d;font-family:monospace;
                           display:flex;align-items:center;justify-content:center;
                           height:100vh;text-align:center;">
            <div>
                <h1>🔒 Session Blocked!</h1>
                <p style="color:#7b8cde;margin-top:10px;">
                    Your session has been blocked for security.<br/>
                    Please login again if this was you.
                </p>
            </div>
        </body></html>
    `);
});

// ── Route: Check session status ───────────────────────────────
app.post("/api/session-status", (req, res) => {
    const { email } = req.body;
    const session   = activeSessions[email];
    if (!session) return res.json({ active: false, frozen: false });
    res.json({ active: true, frozen: session.frozen || false });
});

// ── Route: Health check ───────────────────────────────────────
app.get("/health", (req, res) => {
    res.json({ status: "Backend running!" });
});

// ── Start server ──────────────────────────────────────────────
app.listen(PORT, () => {
    console.log(`\n[✓] Backend running at http://localhost:${PORT}`);
    console.log(`[✓] Open http://localhost:${PORT} in your browser\n`);
});