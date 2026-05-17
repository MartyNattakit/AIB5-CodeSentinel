"""
pipeline/code_analyzer.py
Qwen2.5-Coder 7B + LoRA adapter — converts raw code into structured
vulnerability descriptions that RoBERTa can classify.

Input:  raw code snippet (str)
Output: structured NL description (str)
"""

from __future__ import annotations
from typing import Optional
import torch

# ── Constants ────────────────────────────────────────────────────────────────

BASE_MODEL   = "Qwen/Qwen2.5-Coder-7B-Instruct"
ADAPTER_REPO = "martynattakit/vuln-analyzer-qwen-lora"
MAX_INPUT_CHARS  = 3000   # truncate very long functions before tokenizing
MAX_NEW_TOKENS   = 120    # structured description is short

SYSTEM_PROMPT = (
    "You are a security analyst. Given a code snippet, produce exactly one "
    "structured sentence describing the vulnerability it contains.\n\n"
    "Format: \"This function performs <operation> on <input> without "
    "<missing check>, which may allow an attacker to <impact>.\"\n\n"
    "Be specific about the operation and the missing check. "
    "Do not add any other text."
)

# ── Analyzer class ───────────────────────────────────────────────────────────

class CodeAnalyzer:
    """
    Wraps Qwen2.5-Coder 7B + LoRA adapter for code → description inference.
    Lazy-loaded on first call — model is large (~5GB in 4-bit).
    """

    def __init__(
        self,
        base_model: str = BASE_MODEL,
        adapter_repo: str = ADAPTER_REPO,
        device: Optional[str] = None,
        load_in_4bit: bool = True,
    ):
        self.base_model   = base_model
        self.adapter_repo = adapter_repo
        self.load_in_4bit = load_in_4bit
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        self._model     = None
        self._tokenizer = None

    def _load(self):
        """Lazy load base model + adapter on first inference call."""
        if self._model is not None:
            return

        from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
        from peft import PeftModel

        print(f"[CodeAnalyzer] Loading tokenizer from {self.base_model}...")
        self._tokenizer = AutoTokenizer.from_pretrained(
            self.base_model, trust_remote_code=True
        )
        self._tokenizer.pad_token = self._tokenizer.eos_token

        print(f"[CodeAnalyzer] Loading base model ({self.base_model})...")
        if self.load_in_4bit:
            bnb_config = BitsAndBytesConfig(
                load_in_4bit=True,
                bnb_4bit_quant_type="nf4",
                bnb_4bit_compute_dtype=torch.float16,
                bnb_4bit_use_double_quant=True,
            )
            base = AutoModelForCausalLM.from_pretrained(
                self.base_model,
                quantization_config=bnb_config,
                device_map="auto",
                trust_remote_code=True,
            )
        else:
            base = AutoModelForCausalLM.from_pretrained(
                self.base_model,
                torch_dtype=torch.float16,
                device_map="auto",
                trust_remote_code=True,
            )

        print(f"[CodeAnalyzer] Loading LoRA adapter from {self.adapter_repo}...")
        self._model = PeftModel.from_pretrained(base, self.adapter_repo)
        self._model.eval()
        print("[CodeAnalyzer] Model ready.")

    def analyze(self, code: str) -> str:
        """
        Convert a raw code snippet into a structured vulnerability description.

        Args:
            code: Raw source code (any language).

        Returns:
            Structured description string:
            "This function performs X on Y without Z, which may allow an attacker to W."

        Raises:
            ValueError: If code is empty.
        """
        self._load()

        if not code or not code.strip():
            raise ValueError("Code input cannot be empty.")

        # Truncate very long functions — context window protection
        code_truncated = code[:MAX_INPUT_CHARS]

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": f"Analyze this code:\n\n```\n{code_truncated}\n```"},
        ]

        prompt = self._tokenizer.apply_chat_template(
            messages,
            tokenize=False,
            add_generation_prompt=True,
        )

        inputs = self._tokenizer(prompt, return_tensors="pt").to(self._model.device)

        with torch.no_grad():
            output = self._model.generate(
                **inputs,
                max_new_tokens=MAX_NEW_TOKENS,
                do_sample=False,          # greedy — consistent output
                temperature=1.0,
                pad_token_id=self._tokenizer.eos_token_id,
            )

        # Decode only the newly generated tokens
        new_tokens = output[0][inputs["input_ids"].shape[1]:]
        description = self._tokenizer.decode(
            new_tokens, skip_special_tokens=True
        ).strip()

        # Fallback if output is empty or malformed
        if not description or len(description) < 20:
            description = (
                "This function contains a vulnerability that may allow "
                "an attacker to cause harm. Manual review recommended."
            )

        return description


# ── Module-level singleton ───────────────────────────────────────────────────

_analyzer: Optional[CodeAnalyzer] = None

def get_analyzer() -> CodeAnalyzer:
    """Return the module-level singleton analyzer."""
    global _analyzer
    if _analyzer is None:
        _analyzer = CodeAnalyzer()
    return _analyzer


def analyze(code: str) -> str:
    """Convenience function — analyze without instantiating manually."""
    return get_analyzer().analyze(code)


# ── CLI test ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    test_snippets = [
        ('def get_user(username):\n    query = "SELECT * FROM users WHERE name = \'" + username + "\'"\n    return db.execute(query)', "SQL injection"),
        ('void copy(char *dst, char *src) {\n    strcpy(dst, src);\n}', "Buffer overflow"),
        ('def ping(host):\n    os.system("ping -c 1 " + host)', "Command injection"),
    ]

    analyzer = CodeAnalyzer()
    for code, expected in test_snippets:
        desc = analyzer.analyze(code)
        print(f"Expected: {expected}")
        print(f"Output:   {desc}")
        print()
