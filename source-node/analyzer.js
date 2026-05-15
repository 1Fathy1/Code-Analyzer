const esprima = require("esprima");

/**
 * 🧪 Test Case: يمكنك تغيير الكود هنا لاختبار حالات مختلفة
 * الحالة الحالية تشمل: استعلام آمن (Parameterized) واستعلامات خطرة و XSS و CMD و Exposure و CSRF
 */
const codeToScan = `
query = build_query(x)

cursor.execute(query)
`;

function analysis(code, mode) {
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
    sql: ["execute", "query", "run"],
    xss: ["write", "innerHTML", "send", "render"],
    cmd: ["exec", "spawn", "system"],
    exposure: ["log", "print", "warn"],
  };

  // فحص شامل لوجود أي حماية CSRF في الملف
  const codeString = code.toLowerCase();
  if (
    codeString.includes("csurf") ||
    codeString.includes("csrf") ||
    codeString.includes("antiforgery")
  ) {
    hasCsrfProtection = true;
  }

  tree.body.forEach((node) => {
    // --- 1. تتبع التلوث (Taint Analysis) ---
    if (
      node.type === "ExpressionStatement" &&
      node.expression.type === "AssignmentExpression"
    ) {
      const assign = node.expression;
      if (assign.left.type === "Identifier") {
        const varName = assign.left.name;
        if (isNodeTainted(assign.right, taintedVariables)) {
          taintedVariables.add(varName);
        }
      }
    }

    // --- 2. فحص العمليات الخطرة (Sinks) ---
    if (
      node.type === "ExpressionStatement" &&
      node.expression.type === "CallExpression"
    ) {
      const call = node.expression;
      const methodName =
        call.callee.name ||
        (call.callee.property ? call.callee.property.name : "");

      // فحص SQL, XSS, Command Injection
      if (sinks[mode] && sinks[mode].includes(methodName)) {
        // حل الـ False Positive للـ SQL: لو مبعوت أكتر من Argument يبقى Parameterized (آمن)
        if (mode === "sql" && call.arguments.length > 1) return;

        call.arguments.forEach((arg) => {
          if (isNodeTainted(arg, taintedVariables)) {
            findings.push({
              type:
                mode === "sql"
                  ? "SQL Injection"
                  : mode === "xss"
                    ? "XSS"
                    : "Command Injection",
              line: node.loc.start.line,
              severity: "HIGH",
            });
          }
        });
      }

      // فحص Data Exposure
      if (mode === "exposure" && sinks["exposure"].includes(methodName)) {
        call.arguments.forEach((arg) => {
          if (hasSensitiveName(arg, sensitivePatterns)) {
            findings.push({
              type: "Data Exposure",
              line: node.loc.start.line,
              severity: "MEDIUM",
            });
          }
        });
      }

      // فحص CSRF
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

// دالة مساعدة لتتبع مصدر البيانات (هل هي من input؟)
function isNodeTainted(node, taintedSet) {
  if (!node) return false;

  // 1. لو متغير: بنشوف هل هو في قائمة الملوثين (taintedSet)
  if (node.type === "Identifier") return taintedSet.has(node.name);

  // 2. لو عملية جمع (+): بنشوف لو أي طرف من الطرفين ملوث
  if (node.type === "BinaryExpression") {
    return isNodeTainted(node.left, taintedSet) || isNodeTainted(node.right, taintedSet);
  }

  // 3. التعديل المهم: لو مناداة دالة (CallExpression)
  if (node.type === "CallExpression") {
    const name = node.callee.name || (node.callee.property ? node.callee.property.name : "");
    
    // أ: لو الدالة هي input() فده المصدر الأصلي للتلوث
    if (name === "input") return true;

    // ب: لو دالة وسيطة (زي build_query)، بنشيك على الـ arguments بتاعتها
    // لو أي argument ملوث، بنعتبر نتيجة الدالة ملوثة (Taint Propagation)
    return node.arguments.some((arg) => isNodeTainted(arg, taintedSet));
  }

  return false;
}

// دالة مساعدة لفحص الأسماء الحساسة (للـ Data Exposure)
function hasSensitiveName(node, pattern) {
  if (node.type === "Identifier") return pattern.test(node.name);
  if (node.type === "BinaryExpression")
    return (
      hasSensitiveName(node.left, pattern) ||
      hasSensitiveName(node.right, pattern)
    );
  return false;
}

// تشغيل المحرك على كافة الأنماط وتجميع النتائج
const modes = ["sql", "xss", "cmd", "exposure", "csrf"];
let allFindings = [];
modes.forEach((m) => {
  allFindings = allFindings.concat(analysis(codeToScan, m));
});

// طباعة النتيجة النهائية كـ JSON (المطلوب للمشروع)
console.log(JSON.stringify(allFindings, null, 4));
