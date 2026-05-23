const esprima = require("esprima");

const AVAILABLE_MODES = ["sql", "xss", "cmd", "exposure", "csrf"];

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
    return []; 
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
    if (node.type === "BinaryExpression") return isNodeTainted(node.left) || isNodeTainted(node.right);
    if (node.type === "MemberExpression") {
      const fullPath = getMemberExpressionPath(node);
      if (fullPath.startsWith("req.body") || fullPath.startsWith("req.query") || fullPath.startsWith("req.params")) return true;
      if (node.object && node.object.type === "Identifier") return taintedVariables.has(node.object.name);
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
      if (isNodeTainted(node.init) && node.id.type === "Identifier") taintedVariables.add(node.id.name);
    }
    if (node.type === "AssignmentExpression") {
      if (node.left.type === "Identifier" && isNodeTainted(node.right)) taintedVariables.add(node.left.name);
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
      if (node.hasOwnProperty(key) && typeof node[key] === "object" && node[key] !== null) {
        if (Array.isArray(node[key])) node[key].forEach(child => walk(child));
        else walk(node[key]);
      }
    }
  }

  walk(tree);
  return findings.filter((v, i, a) => a.findIndex(t => (t.type === v.type && t.line === v.line)) === i);
}

const testCases = [
  { id: 1, desc: "Direct SQL Injection", code: `const x = req.query.id;\ndb.query("SELECT * FROM users WHERE id=" + x);`, mode: "sql" },
  { id: 2, desc: "Safe Constant Query", code: `const x = req.query.id;\ndb.query("SELECT * FROM users WHERE id=5");`, mode: "sql" },
  { id: 3, desc: "Intermediate Variable Injection", code: `const x = req.query.id;\nconst query = "SELECT * FROM users WHERE id=" + x;\ndb.query(query);`, mode: "sql" },
  { id: 4, desc: "Taint Propagation", code: `const x = req.query.id;\nconst y = x;\ndb.query("SELECT * FROM users WHERE id=" + y);`, mode: "sql" },
  { id: 5, desc: "Safe Numeric Constant", code: `const x = 10;\ndb.query("SELECT * FROM users WHERE id=" + x.toString());`, mode: "sql" },
  { id: 6, desc: "Deep Propagation", code: `const x = req.query.id;\nconst a = x;\nconst b = "SELECT * FROM users WHERE id=" + a;\nconst c = b;\ndb.query(c);`, mode: "sql" },
  { id: 7, desc: "Parameterized Safe Query", code: `const x = req.query.id;\ndb.query("SELECT * FROM users WHERE id=?", [x]);`, mode: "sql" },
  { id: 8, desc: "Multiple Vulnerabilities", code: `const x = req.query.id;\ndb.query("SELECT * FROM users WHERE id=" + x);\nconst y = req.body.name;\ndb.query("SELECT * FROM products WHERE id=" + y);`, mode: "sql" },
  { id: 9, desc: "Tainted Input directly to Sink", code: `const x = req.query.id;\nconst q = x;\ndb.query(q);`, mode: "sql" },
  { id: 10, desc: "Select All Mode (SQL + XSS + CSRF)", code: `const data = req.query.input;\ndb.query("SELECT * FROM items WHERE id=" + data);\nres.send(data);\napp.post("/login", (req,res)=>{});`, mode: "all" }
];

testCases.forEach((t) => {
  const rawResults = analysis(t.code, t.mode);
  const formattedString = formatOutput(rawResults);
  
  console.log(`--------------------------------------------------`);
  console.log(`ID: ${t.id} | Mode: [${t.mode}] | Desc: ${t.desc}`);
  console.log(`${formattedString}`);
});