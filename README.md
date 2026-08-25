# 🛡️ WebScanner — ML + RAG Security Scanner

> A machine-learning and Retrieval-Augmented Generation (RAG) based web security scanner for detecting common security threats and generating contextual security explanations.

<p align="center">

**Detect → Retrieve → Explain**

</p>

---

## 🚀 Overview

**WebScanner** is a security analysis system that combines:

- 🤖 Machine Learning for attack detection
- 🔎 RAG for retrieving relevant cybersecurity knowledge
- 🧠 LLM-based explanations
- ⚡ Flask REST API
- 🌐 Interactive web interface
- 🧪 Automated testing

The system currently detects:

| Attack Type | Severity |
|---|---|
| 💉 SQL Injection | 🔴 Critical |
| 🕸️ Cross-Site Scripting (XSS) | 🟠 High |
| 🤖 Prompt Injection | 🟠 High |
| ✅ Normal Input | 🟢 Safe |

---

## ✨ Features

### 🤖 ML-Based Detection

The scanner classifies incoming payloads into:

```text
sql_injection
xss
prompt_injection
normal
