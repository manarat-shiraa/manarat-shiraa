"""إعدادات المشروع: المسارات ومتغيرات البيئة."""
import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[2]
load_dotenv(ROOT / ".env")

DATA_DIR = ROOT / "data"
RULES_DIR = ROOT / "rules"

NETWORK_FILE = Path(os.getenv("NETWORK_FILE", DATA_DIR / "network.json"))
ALERTS_FILE = Path(os.getenv("ALERTS_FILE", DATA_DIR / "alerts.json"))
THREAT_INTEL_FILE = DATA_DIR / "threat_intel.json"
SEVERITY_RULES_FILE = RULES_DIR / "severity_rules.json"
MITRE_FILE = RULES_DIR / "mitre_mapping.json"

# طبقة الذكاء الاصطناعي: none (قوالب جاهزة بدون نموذج) | ollama (نموذج محلي) | openai (أي خدمة متوافقة مع OpenAI API)
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "none").lower()
LLM_MODEL = os.getenv("LLM_MODEL", "qwen2.5:7b")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
LLM_TIMEOUT = float(os.getenv("LLM_TIMEOUT", "30"))

# إثراء خارجي اختياري
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
