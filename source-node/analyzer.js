const express = require("express");
const esprima = require("esprima");
const app = express();

app.use(express.json());

// مصفوفة بكل الأنواع المتاحة للفحص عند اختيار "Select All"
const AVAILABLE_MODES = ["sql", "xss", "cmd", "exposure", "csrf"];

function analysis(code, mode) {
  let tree;
  try {
    tree = esprima.parseScript(code, { loc: true });
  } catch (e) {
    return []; // كود غير صحيح قواعدياً
  }

  let findings = [];
  let taintedVariables = new Set();
  let hasCsrfProtection = false;
  const sensitivePatterns = /password|pass|secret|token|key/i;

  const sinks = {
    sql: ["execute", "query", "run"],
    xss: ["write", "innerHTML", "send", "render"],
    cmd: ["exec", "spawn", "system"],
    exposure: ["log", "print", "warn"],
  };

  const codeString = code.toLowerCase();
  if (codeString.includes("csurf") || codeString.includes("csrf") || codeString.includes("antiforgery")) {
    hasCsrfProtection = true;
  }

  // دالة مساعدة لتتبع التلوث
  function isNodeTainted(node) {
    if (!node) return false;
    if (node.type === "Identifier") return taintedVariables.has(node.name);
    if (node.type === "BinaryExpression") {
      return isNodeTainted(node.left) || isNodeTainted(node.right);
    }
    if (node.type === "CallExpression") {
      const name = node.callee.name || (node.callee.property ? node.callee.property.name : "");
      if (name === "input" || name === "req.body" || name === "req.query") return true;
      return node.arguments.some((arg) => isNodeTainted(arg));
    }
    return false;
  }

  // الفحص العابر للـ AST
  tree.body.forEach((node) => {
    if (node.type === "ExpressionStatement" && node.expression.type === "AssignmentExpression") {
      const assign = node.expression;
      if (assign.left.type === "Identifier") {
        if (isNodeTainted(assign.right)) {
          taintedVariables.add(assign.left.name);
        }
      }
    }

    if (node.type === "ExpressionStatement" && node.expression.type === "CallExpression") {
      const call = node.expression;
      const methodName = call.callee.name || (call.callee.property ? call.callee.property.name : "");

      // 1. SQL, XSS, CMD
      if (sinks[mode] && sinks[mode].includes(methodName)) {
        if (mode === "sql" && call.arguments.length > 1) return; // Parameterized = safe

        let isVulnerable = call.arguments.some((arg) => isNodeTainted(arg));
        if (isVulnerable) {
          findings.push({
            type: mode === "sql" ? "SQL Injection" : mode === "xss" ? "XSS" : "Command Injection",
            line: node.loc.start.line,
            severity: "HIGH",
          });
        }
      }

      // 2. Data Exposure
      if (mode === "exposure" && sinks["exposure"].includes(methodName)) {
        let isSensitive = call.arguments.some((arg) => {
          if (arg.type === "Identifier") return sensitivePatterns.test(arg.name);
          return false;
        });
        if (isSensitive) {
          findings.push({
            type: "Data Exposure",
            line: node.loc.start.line,
            severity: "MEDIUM",
          });
        }
      }

      // 3. CSRF
      if (mode === "csrf" && (methodName === "post" || methodName === "put")) {
        if (!hasCsrfProtection) {
          findings.push({
            type: "CSRF (Missing Protection)",
            line: node.loc.start.line,
            severity: "HIGH",
          });
        }
      }
    }
  });

  return findings;
}

// الـ Endpoint المطلوبة للفرونت والباك
app.post("/analyze", (req, res) => {
  const { lan, code, vuln } = req.body;

  if (lan !== "node" && lan !== "javascript") {
    return res.status(400).json({ error: "This endpoint only supports Node.js/Javascript" });
  }

  let finalResults = [];

  // التعديل الذكي لدعم الـ Select All وثغرة معينة في نفس الوقت
  if (vuln === "all") {
    // لو اختار Select All بنلف على كل المودز ونجمع النتائج
    AVAILABLE_MODES.forEach((mode) => {
      finalResults = finalResults.concat(analysis(code, mode));
    });
  } else {
    // لو اختار ثغرة واحدة معينة بنشغل الـ analysis عليها هي بس
    finalResults = analysis(code, vuln);
  }

  return res.json(finalResults);
});

app.listen(3000, () => console.log("Node.js Code Review Service running on port 3000"));