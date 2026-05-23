const express = require("express");
const esprima = require("esprima");
const app = express();

app.use(express.json());

// مصفوفة بكل الأنواع المتاحة للفحص عند اختيار "Select All" أو وضع "all"
const AVAILABLE_MODES = ["sql", "xss", "cmd", "exposure", "csrf"];

// دالة تحويل المخرجات للشكل الصارم المطلوب من تيم السيكيورتي (علامات تنصيص مفردة ومسافات دقيقة)
function formatOutput(findings) {
  if (findings.length === 0) return "[]";

  const formattedObjects = findings.map(item => {
    return `    {\n        'type': '${item.type}',\n        'line': ${item.line},\n        'severity': '${item.severity}'\n    }`;
  });

  return `[\n${formattedObjects.join(",\n")}\n]`;
}

function analysis(code, requestedMode) {
  let tree;
  try {
    tree = esprima.parseScript(code, { loc: true });
  } catch (e) {
    return [{ error: "Syntax Error in code" }]; 
  }

  let findings = [];
  let taintedVariables = new Set();
  let hasCsrfProtection = false;
  const sensitivePatterns = /password|pass|secret|token|key/i;

  const sinks = {
    sql: ["execute", "query", "run", "db.query"],
    xss: ["write", "innerHTML", "send", "render"],
    cmd: ["exec", "spawn", "system"],
    exposure: ["log", "print", "warn", "console.log"],
  };

  const codeString = code.toLowerCase();
  if (codeString.includes("csurf") || codeString.includes("csrf") || codeString.includes("antiforgery")) {
    hasCsrfProtection = true;
  }

  function isNodeTainted(node) {
    if (!node) return false;
    if (node.type === "Identifier") return taintedVariables.has(node.name);
    
    if (node.type === "BinaryExpression") {
      return isNodeTainted(node.left) || isNodeTainted(node.right);
    }
    
    if (node.type === "MemberExpression") {
      const fullPath = getMemberExpressionPath(node);
      if (fullPath.startsWith("req.body") || fullPath.startsWith("req.query") || fullPath.startsWith("req.params")) {
        return true;
      }
      if (node.object && node.object.type === "Identifier") {
        return taintedVariables.has(node.object.name);
      }
    }

    if (node.type === "CallExpression") {
      const name = getMethodName(node);
      if (name === "input") return true;
      return node.arguments.some((arg) => isNodeTainted(arg));
    }
    return false;
  }

  function getMemberExpressionPath(node) {
    if (node.type === "Identifier") return node.name;
    if (node.type === "MemberExpression") {
      const obj = getMemberExpressionPath(node.object);
      const prop = node.computed ? "[]" : (node.property.name || "");
      return obj ? `${obj}.${prop}` : prop;
    }
    return "";
  }

  function getMethodName(node) {
    if (node.callee.type === "Identifier") return node.callee.name;
    if (node.callee.type === "MemberExpression") {
      const fullPath = getMemberExpressionPath(node.callee);
      if (sinks.sql.includes(fullPath) || sinks.exposure.includes(fullPath)) return fullPath;
      return node.callee.property.name || "";
    }
    return "";
  }

  function walk(node) {
    if (!node) return;

    if (node.type === "VariableDeclarator" && node.init) {
      if (isNodeTainted(node.init) && node.id.type === "Identifier") {
        taintedVariables.add(node.id.name);
      }
    }

    if (node.type === "AssignmentExpression") {
      if (node.left.type === "Identifier" && isNodeTainted(node.right)) {
        taintedVariables.add(node.left.name);
      }
    }

    if (node.type === "CallExpression") {
      const methodName = getMethodName(node);
      
      function checkVulnerability(currentMode) {
        if (sinks[currentMode] && sinks[currentMode].includes(methodName)) {
          if (currentMode === "sql" && node.arguments.length > 1) return; 

          if (node.arguments.some((arg) => isNodeTainted(arg))) {
            findings.push({
              type: currentMode === "sql" ? "SQL Injection" : currentMode === "xss" ? "XSS" : "Command Injection",
              line: node.loc ? node.loc.start.line : "Unknown",
              severity: "HIGH",
            });
          }
        }

        if (currentMode === "exposure" && sinks["exposure"].includes(methodName)) {
          let isSensitive = node.arguments.some((arg) => {
            if (arg.type === "Identifier") return sensitivePatterns.test(arg.name);
            if (arg.type === "MemberExpression") return sensitivePatterns.test(getMemberExpressionPath(arg));
            return false;
          });
          if (isSensitive) {
            findings.push({
              type: "Data Exposure",
              line: node.loc ? node.loc.start.line : "Unknown",
              severity: "MEDIUM",
            });
          }
        }

        if (currentMode === "csrf" && (methodName === "post" || methodName === "put")) {
          if (!hasCsrfProtection) {
            findings.push({
              type: "CSRF (Missing Protection)",
              line: node.loc ? node.loc.start.line : "Unknown",
              severity: "HIGH",
            });
          }
        }
      }

      if (requestedMode === "all") {
        AVAILABLE_MODES.forEach(mode => checkVulnerability(mode));
      } else {
        checkVulnerability(requestedMode);
      }
    }

    for (let key in node) {
      if (node.hasOwnProperty(key)) {
        if (typeof node[key] === "object" && node[key] !== null) {
          if (Array.isArray(node[key])) {
            node[key].forEach(child => walk(child));
          } else {
            walk(node[key]);
          }
        }
      }
    }
  }

  walk(tree);
  return findings.filter((v, i, a) => a.findIndex(t => (t.type === v.type && t.line === v.line)) === i);
}

// الـ Endpoint المطلوبة للفرونت والباك
app.post("/analyze", (req, res) => {
  const { lan, code, vuln } = req.body;

  if (lan !== "node" && lan !== "javascript") {
    return res.status(400).json({ error: "This endpoint only supports Node.js/Javascript" });
  }

  // تشغيل الفحص (vuln ممكن تكون اسم ثغرة محددة أو "all")
  const rawResults = analysis(code, vuln);

  // تحويل النتيجة للشكل الصارم المطلوب بالـ Single Quotes
  const finalResponseString = formatOutput(rawResults);

  // إرسال الرد كنص مفرمت يحافظ على شكل الأقواس وعلامات التنصيص
  res.setHeader("Content-Type", "text/plain");
  return res.send(finalResponseString);
});

app.listen(3000, () => console.log("Node.js Code Review Service running on port 3000"));