# Security Interview Questions

This page contains a curated set of security interview questions organized by **experience level**.  
The questions reflect real interview conversations rather than academic topic groupings.

---

## Entry-Level / Foundations

These questions focus on baseline security knowledge and reasoning expected for early-career roles or transitions into security.

- What is the difference between **encryption**, **hashing**, and **encoding**?
- When would you use hashing instead of encryption?
- Why are salts used in password hashing?
- What is the difference between **TCP** and **UDP**?
- What is a **port** and how is it used?
- What does **DNS** do?
- What is **least privilege** and why is it important?
- What is the difference between **authentication** and **authorization**?
- What is a **false positive** versus a **false negative**?
- Walk through the steps you would take after detecting a suspicious login.
- What logs would you review during a potential account compromise?

---

## Engineering-Level (Detection / Security Engineering)

These questions test deeper technical reasoning, implementation decisions, and trade-offs.

- Why might you use `^` in a regular expression?
- What does `$` represent in regex?
- How can poorly written regex impact performance or detections?
- What types of events are high-signal for brute-force activity?
- How do you tune a detection rule to reduce noise?
- What telemetry would you expect from endpoint tools versus network tools?
- How do you design detections that are resilient to attacker evasion?
- What’s the difference between signature-based and behavior-based detection?
- How do you validate a detection rule before pushing it to production?
- When would you automate an investigation versus keeping it manual?
- What risks come with automation in security workflows?

---

## 🧪 Open-Ended / Deep Dive

These questions are often used in senior or final-round interviews.

- How do you balance detection coverage with alert fatigue?
- Describe a time a detection failed. What did you change?
- How would you build a detection program from scratch?
