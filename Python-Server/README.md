
# 🔐 Static Security Analyzer (Multi-Language)

## 📌 Overview

This project is a **Static Application Security Testing (SAST)** tool designed to detect common vulnerabilities without executing the source code.

### Supported Vulnerabilities

- SQL Injection (SQLi)
- Cross-Site Scripting (XSS)
- CSRF (future)
- Data Exposure

The analyzer uses:

- AST Parsing
- Rule-Based Detection
- Basic Taint Analysis

---

# 🧠 Core Concepts

## 1. Source (User Input)

Any untrusted data coming from the user.

### Examples

- Form input
- Request parameters
- API input
- CLI arguments

---

## 2. Sink (Dangerous Operation)

A dangerous function where unsafe data may cause a vulnerability.

### Examples

- SQL execution
- HTML rendering
- Command execution

---

## 3. Data Flow

Tracking untrusted data from:

```text
Source → Variable → Sink
```

---

# 🚨 Detection Logic

```text
IF user input reaches a dangerous function
AND no sanitization is applied
→ Vulnerability detected
```

---

# 🧪 Testing Guidelines

Each implementation must pass all test cases.

---

# 🟢 EASY LEVEL

## 1. Basic SQLi

```python
x = input()

cursor.execute(
    "SELECT * FROM users WHERE id=" + x
)
```

### ✅ Expected

```text
SQL Injection detected
```

---

## 2. Safe Constant Query

```python
x = input()

cursor.execute(
    "SELECT * FROM users WHERE id=5"
)
```

### ✅ Expected

```text
No issues
```

---

# 🟡 MEDIUM LEVEL

## 3. SQLi via Variable

```python
x = input()

query = "SELECT * FROM users WHERE id=" + x

cursor.execute(query)
```

### ✅ Expected

```text
SQL Injection detected
```

---

## 4. Taint Propagation

```python
x = input()

y = x

cursor.execute(
    "SELECT * FROM users WHERE id=" + y
)
```

### ✅ Expected

```text
SQL Injection detected
```

---

## 5. Safe Query (No User Input)

```python
x = 10

cursor.execute(
    "SELECT * FROM users WHERE id=" + str(x)
)
```

### ✅ Expected

```text
No issues
```

---

# 🔴 HARD LEVEL

## 6. Deep Variable Chain

```python
x = input()

a = x

b = "SELECT * FROM users WHERE id=" + a

c = b

cursor.execute(c)
```

### ✅ Expected

```text
SQL Injection detected
```

---

## 7. Parameterized Query (SAFE)

```python
x = input()

cursor.execute(
    "SELECT * FROM users WHERE id=%s",
    x
)
```

### ✅ Expected

```text
No issues
```

---

## 8. Multiple Vulnerabilities

```python
x = input()

cursor.execute(
    "SELECT * FROM users WHERE id=" + x
)

y = input()

cursor.execute(
    "SELECT * FROM products WHERE id=" + y
)
```

### ✅ Expected

```text
2 vulnerabilities detected
```

---

## 9. Edge Case

```python
x = input()

q = x

cursor.execute(q)
```

### ✅ Expected

```text
SQL Injection detected
```

---

### response  of the code must be 

```json
[
    {
        'type': 'SQL Injection',
        'line': 6,
        'severity': 'HIGH'
    }
]
```

# ⚠️ False Positives & False Negatives

## ❌ False Positive

The analyzer reports a vulnerability that does not actually exist.

### Example

```python
cursor.execute(
    "SELECT * FROM users WHERE id=%s",
    x
)
```

### ✅ Expected

```text
No issues
```

---

## ❌ False Negative

The analyzer fails to detect a real vulnerability.

### Example

```python
query = build_query(x)

cursor.execute(query)
```

### ✅ Expected

```text
SQL Injection detected
```

---

# 🎯 Main Goal

The analyzer should:

- Minimize False Positives
- Minimize False Negatives

---

# 🧩 Supported Languages & Parsers

## 🐍 Python

### Primary Parser

- `ast`

### Optional

- `astroid`
- `libcst`

---

## 🟨 Node.js (JavaScript)

### Primary Parsers

- `Babel Parser`
- `Esprima`

### Optional

- `eslint parser`
- `acorn`

---

## 🐘 PHP

### Primary Parser

- `nikic/PHP-Parser`

### Optional

- `Psalm`

---

## ⚙️ C#

### Primary Parser

- `Roslyn`

### Optional

- `SonarAnalyzer`
- `StyleCop`

---

# 🎯 Current Scope (MVP)

- SQL Injection Detection
- Basic Taint Tracking
- Single-file Analysis

---

# ✅ Contribution Rules

Each language implementation must:

- Implement Source Detection
- Implement Sink Detection
- Implement Basic Data Flow Tracking
- Pass All Test Cases

---

# 🔍 Core Analysis Concepts

## 📥 Sources

Examples:

- HTTP parameters
- Request bodies
- Cookies
- Headers
- CLI arguments
- Environment variables

---

## ⚠️ Sinks

Examples:

- `cursor.execute()`
- `eval()`
- `os.system()`

---

## 🔄 Taint Tracking

```python
user_input = request.GET["id"]

query = (
    "SELECT * FROM users WHERE id=" + user_input
)

cursor.execute(query)
```

### Flow

```text
Source → Variable → Query Construction → Sink
```

---

# 🛡️ Analyzer Design Goals

- High accuracy
- Low noise
- Extensible architecture
- Easy rule creation
- Fast scanning performance

---

# 🧪 Testing Strategy

The project should include:

- Vulnerable test cases
- Safe test cases
- Edge cases
- Regression tests

Each rule must validate:

- Expected detections
- Expected safe code

---

# 🔥 Final Goal

Build a lightweight multi-language security analyzer similar to:

- :contentReference[oaicite:0]{index=0}
- :contentReference[oaicite:1]{index=1}
- :contentReference[oaicite:2]{index=2}

