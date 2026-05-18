import os
from dotenv import load_dotenv

# Load .env file from project root
load_dotenv()

# External Threat Intelligence Sources
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API_BASE = "https://api.first.org/data/v1/epss"
KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# API Keys (loaded securely)
NVD_API_KEY = os.getenv("NVD_API_KEY")
