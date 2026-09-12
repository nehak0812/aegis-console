"""MITRE ATLAS tagging — a hand-kept synonym table, validated against the live ATLAS catalogue.

Each reporting item gets the ATLAS technique IDs whose phrases appear in its title/summary, with the matched term kept
so the tag is explainable. IDs are shown with names from the loaded catalogue (collector `mitre_atlas`); an ID that is
not in the catalogue is never shown.
"""
import re

ATLAS_TERMS = [  # (id, fallback name, phrases)
    ("AML.T0051", "LLM Prompt Injection", [r"prompt injection", r"indirect injection"]),
    ("AML.T0054", "LLM Jailbreak", [r"jailbreak"]),
    ("AML.T0010", "AI Supply Chain Compromise", [r"malicious (models?|mcp servers?|ai packages?)", r"poisoned (models?|packages?)", r"model (hub|repository) (malware|poisoning)", r"pickle (exploit|malware|deserializ)"]),
    ("AML.T0011.002", "Poisoned AI Agent Tool", [r"(malicious|poisoned|rogue|backdoored) (mcp|agent tools?|ai extensions?)"]),
    ("AML.T0053", "AI Agent Tool Invocation", [r"agent tool (abuse|invocation|misuse)", r"tool[- ]call (injection|hijack)"]),
    ("AML.T0055", "Unsecured Credentials", [r"(ai|llm|openai|anthropic|api) keys? (leak|exposed|stolen|theft)", r"(leaked|stolen|exposed) (api|ai|llm) keys?", r"llmjacking"]),
    ("AML.T0096", "AI Service API", [r"(ai|llm|openai|claude|gemini)[- ]api (as|for) (c2|command)", r"ai services? (as|for) (c2|command)"]),
    ("AML.T0060", "Publish Hallucinated Entities", [r"slopsquat", r"hallucinated (packages?|dependenc)"]),
    ("AML.T0040", "AI Model Inference API Access", [r"distillation (attacks?|campaigns?)", r"model extraction"]),
    ("AML.T0020", "Training Data Poisoning", [r"data poisoning", r"training[- ]data poison"]),
    ("AML.T0080", "AI Agent Context Poisoning", [r"(memory|context) poisoning"]),
]
_C = [(i, n, re.compile("|".join(f"(?:{p})" for p in ps), re.I)) for i, n, ps in ATLAS_TERMS]


def atlas_for(text: str) -> list[dict]:
    out = []
    for i, n, rx in _C:
        m = rx.search(text or "")
        if m:
            out.append({"id": i, "term": m.group(0).lower()})
    return out
