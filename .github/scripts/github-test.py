import os
import sys
import requests
import json
import base64
import gzip
import time

# =============================================================================
# CONFIG
# =============================================================================

GITHUB_TOKEN = os.getenv("GH_TOKEN")
GITHUB_OWNER = os.getenv("GH_OWNER")
GITHUB_REPO = os.getenv("GH_REPO")
GITHUB_BRANCH = os.getenv("GH_BRANCH", "main")

# Token kontrolü
if not GITHUB_TOKEN:
    print("❌ Hata: GH_TOKEN bulunamadı! Secret ayarlarını kontrol edin.")
    sys.exit(1)

# Jira Verisini Al
try:
    jira_payload = os.getenv("JIRA_DATA")
    if jira_payload:
        single_issue = json.loads(jira_payload)
        JIRA_ISSUES = [single_issue]
    else:
        # Test için dummy data (Eğer environment boşsa)
        print("⚠️ Uyarı: JIRA_DATA bulunamadı, test verisi kullanılıyor.")
        JIRA_ISSUES = [] 
except Exception as e:
    print(f"❌ JSON Parse Hatası: {e}")
    sys.exit(1)


def create_sarif(issues):
    """Create SARIF with safe data handling (No KeyErrors)"""
    
    upload_timestamp = str(int(time.time()))

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Jira Pentest Integration",
                    "semanticVersion": "1.0.0",
                    "rules": []
                }
            },
            "results": []
        }]
    }

    if not issues:
        return sarif

    run = sarif["runs"][0]

    for idx, issue in enumerate(issues):
        # 'custom' alanı yoksa boş sözlük ata
        c = issue.get("custom", {})
        
        # GÜVENLİ VERİ ALIMI (.get metodu)
        # Eğer veri yoksa ikinci parametredeki varsayılan metni kullanır.
        key = issue.get("key", "UNKNOWN")
        summary = issue.get("summary", "No Summary")
        desc = c.get("description", "No description provided.")
        impact = c.get("impact", "See Jira task for impact details.")
        remediation = c.get("remediation", "See Jira task for remediation.")
        poc = c.get("poc", "No PoC provided.")
        cvss = c.get("cvss", "0.0")
        cvss_vector = c.get("cvss_vector", "N/A")
        cwe_id = c.get("cwe_id", "CWE-000")
        jira_url = c.get("jira_url", "#")
        file_path = c.get("file", "unknown_location")
        line_num = c.get("line", 1)

        rule_id = f"JIRA-{key}"

        # 1. KURAL TANIMI (Rule Definition)
        rule = {
            "id": rule_id,
            "name": key,
            "shortDescription": {
                "text": summary
            },
            "fullDescription": {
                "text": f"{desc}\n\nImpact: {impact}"
            },
            "help": {
                "text": f"JIRA Task: {key}\nCVSS: {cvss}\nRemediation: {remediation}",
                "markdown": f"# {summary}\n\n{desc}\n\n## Impact\n{impact}\n\n## Remediation\n{remediation}\n\n[View in Jira]({jira_url})"
            },
            "defaultConfiguration": {
                "level": "error" 
            },
            "properties": {
                "security-severity": cvss
            }
        }
        run["tool"]["driver"]["rules"].append(rule)

        # 2. SONUÇ (Result)
        result = {
            "ruleId": rule_id,
            "ruleIndex": idx,
            "level": "error",
            "message": {
                "text": f"{summary} (CVSS {cvss})"
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": file_path,
                        "uriBaseId": "%SRCROOT%"
                    },
                    "region": {
                        "startLine": int(line_num),
                        "endLine": int(line_num)
                    }
                }
            }],
            "partialFingerprints": {
                "primaryLocationLineHash": f"{key}-{upload_timestamp}"
            }
        }
        run["results"].append(result)

    return sarif


def upload(sarif_data):
    """Upload to GitHub Code Scanning API"""
    
    if not GITHUB_TOKEN:
        return False

    print("📍 Getting commit info...")
    try:
        r = requests.get(
            f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/commits/{GITHUB_BRANCH}",
            headers={
                "Authorization": f"Bearer {GITHUB_TOKEN}",
                "Accept": "application/vnd.github+json"
            }
        )
        
        if r.status_code != 200:
            print(f"❌ Commit alınamadı: {r.status_code} - {r.text}")
            return False

        commit_sha = r.json()["sha"]
        print(f"   ✅ Commit SHA: {commit_sha[:8]}")

        print("\n📦 Compressing SARIF...")
        sarif_json = json.dumps(sarif_data)
        sarif_gzip = gzip.compress(sarif_json.encode())
        sarif_b64 = base64.b64encode(sarif_gzip).decode()

        print("📤 Uploading to Code Scanning...")
        r = requests.post(
            f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/code-scanning/sarifs",
            headers={
                "Authorization": f"Bearer {GITHUB_TOKEN}",
                "Accept": "application/vnd.github+json"
            },
            json={
                "commit_sha": commit_sha,
                "ref": f"refs/heads/{GITHUB_BRANCH}",
                "sarif": sarif_b64,
                "tool_name": "Jira Integration"
            }
        )

        if r.status_code == 202:
            print("✅ SUCCESS! Rapor başarıyla yüklendi.")
            print(f"🔍 Sonuçları şurada görün: https://github.com/{GITHUB_OWNER}/{GITHUB_REPO}/security/code-scanning")
            return True
        else:
            print(f"❌ Upload Hatası: {r.status_code}\n{r.text}")
            return False
            
    except Exception as e:
        print(f"❌ Bağlantı Hatası: {e}")
        return False


def main():
    print("=" * 60)
    print("🔒 JIRA TO GITHUB SECURITY SCANNING")
    print("=" * 60)

    if not JIRA_ISSUES:
        print("ℹ️ İşlenecek veri yok, çıkılıyor.")
        return

    print(f"\n🔄 {len(JIRA_ISSUES)} adet bulgu işleniyor...")
    sarif = create_sarif(JIRA_ISSUES)

    if upload(sarif):
        print("\n✅ İŞLEM TAMAMLANDI")
    else:
        print("\n❌ İŞLEM BAŞARISIZ")
        sys.exit(1)

if __name__ == "__main__":
    main()
