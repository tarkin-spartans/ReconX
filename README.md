# 🔍 ReconX - Advanced OSINT & Secret Finder  

ReconX is an **ultra-fast** and **multi-threaded** OSINT reconnaissance tool designed to:  
✅ Fetch **all URLs** from open-source intelligence (OSINT) sources.  
✅ Extract **JavaScript & JSON** files for manual analysis.  
✅ Scan for **secrets** (API keys, JWT tokens, AWS keys, etc.).  
✅ Extract **subdomains** from public sources.  
✅ Save all findings in well-structured files for easy review.  

---

## 🚀 Features  
✅ **Retrieve URLs** from OSINT sources (AlienVault, URLScan, Wayback Machine).  
✅ **Extract JavaScript & JSON files** for further manual inspection.  
✅ **Find secrets** (AWS keys, Google API, Slack tokens, JWT, etc.).  
✅ **Extract subdomains** from crt.sh, VirusTotal, and other sources.  
✅ **Super fast performance** with **multithreading** & **rate-limiting**.  
✅ **Structured output files** for better analysis.  

---

## 🛠 Installation  

### 🔥 **Install Dependencies**  
ReconX requires **Python 3.x** and a few libraries. Install them with:  
sudo apt update && sudo apt install python3 python3-pip -y
pip3 install requests argparse concurrent.futures

For BlackArch users:
sudo pacman -S python-pip
pip install requests argparse concurrent.futures

🔥 Clone the Tool

git clone https://github.com/tarkin-spartans/ReconX
cd ReconX
chmod +x reconx.py
