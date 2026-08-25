\# RAG Security Scanner



A machine-learning and Retrieval-Augmented Generation (RAG) based security scanner for detecting common security threats in web and AI applications.



The system combines a trained ML classifier with a FAISS-based security knowledge retrieval system and an LLM-powered explanation layer through OpenRouter.



\---



\## 1. Project Overview



Modern web and AI applications can be exposed to different types of malicious input such as:



\- SQL Injection

\- Cross-Site Scripting (XSS)

\- Prompt Injection



Manually analyzing these payloads can be difficult and time-consuming.



This project provides an automated security scanning pipeline that:



1\. Accepts a user-supplied payload.

2\. Classifies the payload using a machine-learning model.

3\. Calculates a confidence score.

4\. Retrieves relevant cybersecurity knowledge using RAG.

5\. Uses an LLM to generate a human-readable security explanation.

6\. Assigns a severity level.

7\. Displays the result through a web interface.



\---



\## 2. System Architecture



```text

&#x20;                   ┌─────────────────────┐

&#x20;                   │     Web Interface   │

&#x20;                   │   HTML + CSS + JS   │

&#x20;                   └──────────┬──────────┘

&#x20;                              │

&#x20;                              │ POST /scan

&#x20;                              ▼

&#x20;                   ┌─────────────────────┐

&#x20;                   │     Flask API       │

&#x20;                   │      /scan          │

&#x20;                   └──────────┬──────────┘

&#x20;                              │

&#x20;                              ▼

&#x20;                   ┌─────────────────────┐

&#x20;                   │   ML Attack         │

&#x20;                   │   Detector          │

&#x20;                   └──────────┬──────────┘

&#x20;                              │

&#x20;                   ┌──────────┴──────────┐

&#x20;                   │                     │

&#x20;                   ▼                     ▼

&#x20;             Attack Detected          Normal

&#x20;                   │                     │

&#x20;                   ▼                     ▼

&#x20;             ┌───────────┐          SAFE Response

&#x20;             │    RAG    │

&#x20;             │ Retriever │

&#x20;             └─────┬─────┘

&#x20;                   │

&#x20;                   ▼

&#x20;             ┌─────────────┐

&#x20;             │    FAISS    │

&#x20;             │ Vector Index│

&#x20;             └──────┬──────┘

&#x20;                    │

&#x20;                    ▼

&#x20;             Relevant Security

&#x20;                 Knowledge

&#x20;                    │

&#x20;                    ▼

&#x20;             ┌─────────────┐

&#x20;             │  OpenRouter │

&#x20;             │     LLM     │

&#x20;             └──────┬──────┘

&#x20;                    │

&#x20;                    ▼

&#x20;             Security Explanation

&#x20;                    │

&#x20;                    ▼

&#x20;               JSON Response

&#x20;                    │

&#x20;                    ▼

&#x20;                Web UI

