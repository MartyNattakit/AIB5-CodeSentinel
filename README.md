---
title: CodeSentinel
emoji: 🛡️
colorFrom: green
colorTo: gray
sdk: docker
app_port: 7860
pinned: false
---

# CodeSentinel

Vulnerability classification tool combining fine-tuned ML models with MITRE framework coverage.

Paste a **code snippet**, **CVE description**, or **bug report** — CodeSentinel identifies the vulnerability type, severity, and (for AI/ML inputs) the relevant ATLAS attack technique.

## What it does

- **Code input** → Qwen2.5-Coder 7B analyzes the code → RoBERTa classifies the CWE
- **Text input** → RoBERTa classifies directly from the description
- **AI/ML input** → ATLAS pattern matcher identifies the relevant attack technique

## Models

| Model | Purpose | Accuracy |
|-------|---------|----------|
| [`martynattakit/vuln-classifier-roberta`](https://huggingface.co/martynattakit/vuln-classifier-roberta) | CWE classification from text | Macro F1: 0.850 |
| [`martynattakit/vuln-analyzer-qwen-lora`](https://huggingface.co/martynattakit/vuln-analyzer-qwen-lora) | Code → vulnerability description | Eval loss: — |

## Coverage

**CWE Top 25** (MITRE 2024):
CWE-787, CWE-79, CWE-89, CWE-416, CWE-78, CWE-20, CWE-125, CWE-22, CWE-352, CWE-434, CWE-862, CWE-476, CWE-287, CWE-190, CWE-502, CWE-77, CWE-119, CWE-798, CWE-918, CWE-306, CWE-362, CWE-269, CWE-94, CWE-863, CWE-276

**MITRE ATLAS** (25 techniques):
Prompt injection, data poisoning, model extraction, membership inference, adversarial examples, jailbreaking, and more.

## Known limitations

- **CWE-77**: 0 F1 — insufficient training samples. Predictions for this class are unreliable.
- **CWE-863**: F1 0.60 — semantic overlap with CWE-862 makes these hard to distinguish.
- **ATLAS matching** uses keyword signals + retrieval, not a fine-tuned classifier. Confidence scores reflect signal overlap, not ground-truth accuracy. No labeled ATLAS dataset exists yet.
- **Code analysis** training data is primarily C/C++ (BigVul). Python/JS/Go descriptions may be less precise.

## Stack

```
RoBERTa-base        fine-tuned on 165k CVE→CWE pairs (xamxte/cve-to-cwe)
Qwen2.5-Coder-7B    QLoRA fine-tuned on BigVul (1,596 samples)
ATLAS matcher       keyword RAG over 25 hand-crafted MITRE case studies
FastAPI             REST API backend
```

## Local development

```bash
pip install -r requirements.txt
python app.py
# → http://localhost:7860
```

## Project structure

```
pipeline/
    classifier.py      RoBERTa inference wrapper
    code_analyzer.py   Qwen inference wrapper  
    atlas_matcher.py   ATLAS pattern matcher
    router.py          Input routing + output card
api/
    main.py            FastAPI endpoints
frontend/
    index.html         Web UI
data/
    atlas_cases.json   25 MITRE ATLAS techniques (hand-crafted)
notebooks/
    01_roberta_finetune.ipynb
    02_qwen_qlora.ipynb
```

## Links
- [Try the application here!](https://huggingface.co/spaces/martynattakit/CodeSentinel-CWE_Classification)
- [Medium Blog](https://medium.com/@martyxc2018/codesentinel-ai-cwe-classification-a3ed88f2be28)

## Acknowledgements

- **My mentor and TA from AI Builders 2025**
  For making this project possible by giving me guidances, feedbacks throughout the development of this project.
