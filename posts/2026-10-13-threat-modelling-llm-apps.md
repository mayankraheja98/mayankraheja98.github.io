---
title: Threat modelling an LLM app: where to start
date: 2026-10-13
tags: [AI Security, Threat Modelling]
summary: A practical starting checklist for securing LLM-powered features: trust boundaries, untrusted input, tools, and data.
sample: true
---

LLM features look like "just another API call", but they change the threat model. The model reads **untrusted text** and may act on it. Start there.

## 1. Draw the trust boundaries

List every source of text that reaches the model: user input, retrieved documents (RAG), web pages, emails, tool outputs, and prior conversation. Treat all of it as **untrusted**, including content from your own database if users can write to it.

## 2. Map what the model can do

For each tool or action the model can trigger, ask:

- What is the worst thing it could do if the prompt is fully attacker-controlled?
- Does it run with the user's permissions or a broad service account?
- Does a human approve high-impact actions?

## 3. Check the classic risks (OWASP LLM Top 10)

1. Prompt injection (direct and indirect)
2. Sensitive information disclosure
3. Insecure output handling (model output rendered or executed downstream)
4. Excessive agency
5. Supply chain: models, datasets, plugins

## 4. Add guardrails that don't depend on the model

> Don't rely on "please ignore malicious instructions" in the system prompt. Enforce limits in code.

- Least-privilege tool credentials, scoped per user
- Allow-lists for tools, domains and file paths
- Output validation and encoding before rendering or executing
- Logging of prompts, tool calls and decisions for detection and review

## 5. Put it in the pipeline

Bring this into DevSecOps: threat model at design review, automated tests with injection payloads in CI, and monitoring in production.
