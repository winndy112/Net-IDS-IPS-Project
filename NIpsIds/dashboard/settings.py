
from pathlib import Path
import os
from dotenv import load_dotenv

load_dotenv()

# Base paths
BASE_DIR = Path(__file__).resolve().parent.parent.parent
LOG_DIR = "log"
ALERT_DIR = os.path.join(LOG_DIR, "alert_fast")

# Snort configuration
RULESET_DIR = "/usr/local/etc/rules/"
SNORT_CONF_PATH = '/usr/local/etc/snort/snort.lua'
DEFAULT_DAQ_MODULE = "afpacket"

# MISP configuration
MISP_URL = os.getenv('MISP_URL', 'https://localhost')
MISP_API_KEY = os.getenv('API_KEY')
MISP_VERIFY_CERT = False

# Rule categories
RULE_CATEGORIES = {
    'spyware-adware': ['spyware', 'adware'],
    'phishing': ['phishing'],
    'exploit': ['exploit'],
    'ransomware': ['ransomware', 'ransom'],
    'malware': ['malware'],
    'apt': ['apt', 'apt-', 'apt0', 'apt1', 'apt2', 'apt3', 'apt4', 'apt5', 'apt6', 'apt7', 'apt8', 'apt9']
}