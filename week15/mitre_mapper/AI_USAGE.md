AI Usage Log
Project: Malware Behavior → MITRE ATT&CK Technique Mapper

Overview
This document documents my use of AI tools (primarily ChatGPT, with some IDE‑based code suggestions) during the development of the Malware Behavior Mapper capstone project.
AI was used as a development assistant for brainstorming, scaffolding, and troubleshooting. All AI‑generated suggestions were reviewed, tested, and modified as needed. Final architectural decisions, validation logic, and behavior mapping rules were designed and implemented by me.
The goal was to accelerate development without sacrificing correctness, explainability, or understanding.

Summary Statistics

Total AI-assisted sessions: 13
Code accepted as-is: 4
Code modified before use: 6
Code rejected: 3
Primary AI use cases:

Initial class structure ideas
CLI argument planning
Unit test suggestions
Debugging logic errors




Key Prompts & Interactions
✅ Week 13 – Planning & Design
Prompt:
“Design a simple Python tool that maps malware behaviors to MITRE ATT&CK techniques using rule-based logic.”
AI Response (Summary):
Suggested high-level architecture including:

A behavior model class
A mapping component
JSON input/output

My Action:
✅ Modified
I accepted the overall structure idea but redesigned the mapper to:

Use normalized behavior names
Include confidence scoring
Preserve explainability rather than complex heuristics


✅ Week 14 – Implementation
Prompt:
“Write a Python class that maps API calls like CreateRemoteThread to ATT&CK techniques.”
AI Response (Summary):
Provided a basic conditional mapping example.
My Action:
✅ Modified
I refactored the suggestion into the AttackTechniqueMapper class using:

Dictionary‑based rule mappings
Behavior type separation
Confidence scores per technique

This improved extensibility and readability.

✅ Week 15 – Testing & Validation
Prompt:
“Generate pytest unit tests for mapping malware behaviors to ATT&CK techniques.”
AI Response (Summary):
Suggested basic test cases for positive mappings.
My Action:
✅ Modified
I expanded the tests to include:

Unmapped behavior handling
Empty behavior list edge case
Validation failures in utilities

This ensured the tool behaved correctly under non‑ideal conditions.

Examples of Modified / Rejected AI Code
Example 1: Mapping Logic (Modified)
Original AI Suggestion:

if behavior.value == "CreateRemoteThread":
    return "T1055"


My Modified Version:


elf.mapping_rules = {
    "api_call": {
        "CreateRemoteThread": ("T1055", 0.9),
        "VirtualAllocEx": ("T1055", 0.8),
    }
}


Why I Changed It:
The AI suggestion hard‑coded logic that did not scale.
I replaced it with a structured rule dictionary that:

Supports multiple behavior types
Allows confidence scoring
Can be easily extended without modifying logic flow

Verification Methods
To validate AI‑assisted code suggestions, I used:

✅ Pytest unit tests for all core mapping logic
✅ Manual execution using known sample inputs
✅ JSON output validation against expected structure
✅ Code review to ensure I fully understood every line
✅ Edge‑case testing (unmapped behaviors, empty inputs)

No AI‑suggested code was committed without verification.

Reflection: Responsible AI Use
This project taught me that AI is most effective when used as a starting point, not an authority.
AI helped me think faster about structure and testing, but it often suggested overly simplistic logic that did not account for real‑world edge cases.
I learned to ask better prompts, such as requesting design ideas instead of final code, and to critically evaluate every suggestion. The most important habit I developed was asking: “Would I be comfortable explaining this code in an interview?” If not, I rewrote it.
Using AI responsibly meant maintaining full ownership of architectural decisions, validating all behavior through testing, and prioritizing explainable, deterministic logic — which is especially important in security tooling.