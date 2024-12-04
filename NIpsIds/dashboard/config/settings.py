
from pathlib import Path
import os
from dotenv import load_dotenv

load_dotenv()

# Base paths
BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent
RULESET_DIR = "/usr/local/etc/rules/"
SNORT_CONF_PATH = '/usr/local/etc/snort/snort.lua'
LOG_BASE_PATH = "log"
ALERT_PATH = os.path.join(LOG_BASE_PATH, "alert_fast")

# MISP Settings
MISP_URL = os.getenv('MISP_URL', 'https://localhost')
MISP_API_KEY = os.getenv('API_KEY')
MISP_VERIFY_CERT = False

# Snort default settings
DEFAULT_DAQ_MODULE = "afpacket"

# Rule categories
RULE_CATEGORIES = {
    'spyware-adware': ['spyware', 'adware'],
    'phishing': ['phishing'],
    'exploit': ['exploit'],
    'ransomware': ['ransomware', 'ransom'],
    'malware': ['malware'],
    'apt': ['apt', 'apt-', 'apt0', 'apt1', 'apt2', 'apt3', 'apt4', 'apt5', 'apt6', 'apt7', 'apt8', 'apt9']
}