const express = require('express');
const cors = require('cors');
const esprima = require('esprima');

const app = express();
const PORT = 4000; // السيرفر هيشتغل على بورت 4000

// تفعيل الـ CORS عشان أي سيرفر تاني أو الـ React يكلمه بدون حظر
app.use(cors());
app.use(express.json());

// 🛡️ كلاس الـ Analyzer بتاعكِ المظبوط بالـ Keys الجديدة
class AwareXNodeAnalyzer {
  constructor() {
    this.findings = [];
    this.taintedVars = new Set();
    this.hasCsrfMiddleware = false;
    this.mode = "";
  }

  isNodeTainted(node) {
    if (!node) return false;
    if (node.type === "MemberExpression") {
      let obj = node.object;
      if (obj.type === "MemberExpression" && obj.object.name === "req") {
        if (["body", "query", "params", "headers"].includes(obj.property.name))
          return true;
      }
      if (
        obj.name === "req" &&
        ["body", "query", "params"].includes(node.property.name)
      )
        return true;
    }
    if (node.type === "Identifier" && this.taintedVars.has(node.name))
      return true;
    if (node.type === "BinaryExpression" && node.operator === "+")
      return this.isNodeTainted(node.left) || this.isNodeTainted(node.right);
    if (node.type === "TemplateLiteral") {
      for (let expr of node.expressions) {
        if (this.isNodeTainted(expr)) return true;
      }
    }
    return false;
  }

  traverse(node) {
    if (!node) return;

    if (node.type === "VariableDeclarator" && node.init) {
      if (node.id.type === "Identifier" && this.isNodeTainted(node.init))
        this.taintedVars.add(node.id.name);
      if (node.id.type === "ObjectPattern" && this.isNodeTainted(node.init)) {
        node.id.properties.forEach((prop) => {
          if (prop.value && prop.value.type === "Identifier")
            this.taintedVars.add(prop.value.name);
        });
      }
    }

    if (
      node.type === "CallExpression" &&
      node.callee.name === "app" &&
      node.callee.property?.name === "use"
    ) {
      let arg = node.arguments[0];
      if (
        arg &&
        (arg.name?.toLowerCase().includes("csrf") ||
          arg.callee?.name?.toLowerCase().includes("csrf"))
      )
        this.hasCsrfMiddleware = true;
    }

    if (node.type === "CallExpression") {
      let funcName =
        node.callee.type === "Identifier"
          ? node.callee.name
          : node.callee.property?.name;

      if (
        this.mode === "sql" &&
        ["query", "execute", "raw"].includes(funcName)
      ) {
        if (this.isNodeTainted(node.arguments[0]))
          this.addFinding(
            "SQL Injection",
            node.loc?.start.line || 0,
            "CRITICAL",
          );
      }
      if (
        this.mode === "command" &&
        ["exec", "execSync", "spawn", "spawnSync"].includes(funcName)
      ) {
        if (this.isNodeTainted(node.arguments[0]))
          this.addFinding(
            "Command Injection",
            node.loc?.start.line || 0,
            "CRITICAL",
          );
      }
      if (
        this.mode === "xss" &&
        ["send", "write", "render"].includes(funcName)
      ) {
        for (let arg of node.arguments) {
          if (this.isNodeTainted(arg)) {
            this.addFinding(
              "Cross-Site Scripting (XSS)",
              node.loc?.start.line || 0,
              "HIGH",
            );
            break;
          }
        }
      }
      if (this.mode === "exposure" && funcName === "createHash") {
        if (
          node.arguments[0] &&
          ["md5", "sha1"].includes(node.arguments[0].value)
        )
          this.addFinding(
            "Sensitive Data Exposure (Weak Hashing)",
            node.loc?.start.line || 0,
            "MEDIUM",
          );
      }
    }

    for (let key in node) {
      if (node[key] && typeof node[key] === "object") {
        if (Array.isArray(node[key]))
          node[key].forEach((child) => this.traverse(child));
        else this.traverse(node[key]);
      }
    }
  }

  addFinding(type, line, severity) {
    this.findings.push({ line: line, severity: severity, type: type });
  }

  analyze(userCode, userMode) {
    this.findings = [];
    this.taintedVars.clear();
    this.hasCsrfMiddleware = false;
    this.mode = userMode.toLowerCase().trim();
    try {
      const ast = esprima.parseScript(userCode, { loc: true });
      this.traverse(ast);
      if (this.mode === "csrf" && !this.hasCsrfMiddleware)
        this.addFinding("Missing CSRF Middleware Protection", 1, "HIGH");
      
      return {
        status: "success",
        vulnerabilities: this.findings,
      };
    } catch (err) {
      return { status: "error", message: err.message };
    }
  }
}

// 🌐 الـ Endpoint اللي تيم الباك إند هيستدعيها
app.post('/api/analyze/node', (req, res) => {
    const { code, mode } = req.body;

    if (!code || !mode) {
        return res.status(400).json({ status: "error", message: "المعاملات المرسلة (code أو mode) ناقصة!" });
    }

    const analyzer = new AwareXNodeAnalyzer();
    const result = analyzer.analyze(code, mode);

    return res.json(result);
});

// تشغيل السيرفر
app.listen(PORT, () => {
    console.log(`🚀 Node.js Analyzer Microservice is running on: http://localhost:${PORT}`);
});