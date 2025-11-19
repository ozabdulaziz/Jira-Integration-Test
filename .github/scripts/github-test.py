import requests
import json
import base64
import gzip
import sys
import time

# =============================================================================
# CONFIG
# =============================================================================

GITHUB_TOKEN = os.getenv("GH_TOKEN")
GITHUB_OWNER = os.getenv("GH_OWNER")
GITHUB_REPO = os.getenv("GH_REPO")
GITHUB_BRANCH = "main" # veya os.getenv("GH_BRANCH")

try:
    jira_payload = os.getenv("JIRA_DATA")
    if jira_payload:
        # Jira tek bir issue gönderir, biz onu listeye çeviririz
        single_issue = json.loads(jira_payload)
        JIRA_ISSUES = [single_issue]
    else:
        print("❌ Hata: JIRA_DATA environment değişkeni bulunamadı!")
        sys.exit(1)
except Exception as e:
    print(f"❌ JSON Parse Hatası: {e}")
    sys.exit(1)

# ... Geri kalan create_sarif, upload ve main fonksiyonları AYNI KALSIN ...


def create_sarif(issues):
    """Create beautiful SARIF with rich formatting"""

    # Unique timestamp for this upload
    upload_timestamp = str(int(time.time()))

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Getir Security Team - Penetration Test",
                    "semanticVersion": "3.0.0",
                    "informationUri": "https://security.getir.com",
                    "organization": "Getir Cybersecurity Operations",
                    "rules": []
                }
            },
            "results": []
        }]
    }

    run = sarif["runs"][0]

    for idx, issue in enumerate(issues):
        c = issue["custom"]
        rule_id = f"PENTEST-{issue['key']}"

        # Beautiful rule
        rule = {
            "id": rule_id,
            "name": issue["key"].replace("-", "_"),
            "shortDescription": {
                "text": issue["summary"]
            },
            "fullDescription": {
                "text": f"{c['description']}\n\n{c['impact']}"
            },
            "help": {
                "text": f"JIRA: {issue['key']}\nCVSS: {c['cvss']} ({c['cvss_vector']})\nCWE: {c['cwe_id']} - {c['cwe_name']}\nOWASP: {c['owasp']}\n\n{c['remediation']}",
                "markdown": f"# {issue['summary']}\n\n{c['description']}\n\n## Impact\n\n{c['impact']}\n\n## Proof of Concept\n\n{c['poc']}\n\n## Remediation\n\n{c['remediation']}\n\n## Metadata\n\n- **JIRA:** [{issue['key']}]({c['jira_url']})\n- **CVSS:** {c['cvss']} `{c['cvss_vector']}`\n- **CWE:** {c['cwe_id']} - {c['cwe_name']}\n- **OWASP:** {c['owasp']}\n- **Assignee:** {issue['assignee']}\n- **Status:** {issue['status']}\n- **Effort:** {c['effort']}\n- **Risk:** {c['risk']}\n- **Compliance:** {c['compliance']}"
            },
            "defaultConfiguration": {
                "level": {"critical": "error", "high": "error", "medium": "warning", "low": "note"}[issue["severity"]]
            },
            "properties": {
                "tags": issue["labels"],
                "precision": "very-high",
                "security-severity": c["cvss"]
            }
        }
        run["tool"]["driver"]["rules"].append(rule)

        # Beautiful result message - SHORT!
        result = {
            "ruleId": rule_id,
            "ruleIndex": idx,
            "level": {"critical": "error", "high": "error", "medium": "warning", "low": "note"}[issue["severity"]],
            "message": {
                "text": f"[{issue['severity'].upper()}] {issue['summary']} - CVSS {c['cvss']} | {c['cwe_id']} | JIRA: {issue['key']} ({c['jira_url']}) | Assignee: {issue['assignee']} | {c['owasp']}"
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": c["file"],
                        "uriBaseId": "%SRCROOT%"
                    },
                    "region": {
                        "startLine": c["line"]
                    }
                }
            }],
            "partialFingerprints": {
                "primaryLocationLineHash": f"{issue['key']}-{upload_timestamp}"
            },
            "properties": {
                "jira_key": issue["key"],
                "jira_url": c["jira_url"],
                "security-severity": c["cvss"],
                "cvss_vector": c["cvss_vector"],
                "cwe_id": c["cwe_id"],
                "cwe_name": c["cwe_name"],
                "owasp": c["owasp"],
                "priority": issue["priority"],
                "severity": issue["severity"],
                "status": issue["status"],
                "assignee": issue["assignee"],
                "effort": c["effort"],
                "risk_level": c["risk"],
                "compliance_violations": c["compliance"]
            }
        }
        run["results"].append(result)

    return sarif


def upload(sarif_data):
    """Upload to GitHub"""

    print("📍 Getting commit...")
    r = requests.get(
        f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/commits/{GITHUB_BRANCH}",
        headers={
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "Accept": "application/vnd.github+json"
        }
    )

    if r.status_code != 200:
        print(f"❌ Error: {r.status_code}")
        return False

    commit_sha = r.json()["sha"]
    print(f"   ✅ {commit_sha[:8]}")

    print("\n📦 Compressing SARIF...")
    sarif_gzip = gzip.compress(json.dumps(sarif_data).encode())
    sarif_b64 = base64.b64encode(sarif_gzip).decode()

    print("📤 Uploading...")
    r = requests.post(
        f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/code-scanning/sarifs",
        headers={
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "Accept": "application/vnd.github+json"
        },
        json={
            "commit_sha": commit_sha,
            "ref": f"refs/heads/{GITHUB_BRANCH}",
            "sarif": sarif_b64
        }
    )

    if r.status_code == 202:
        print("✅ SUCCESS!")
        print(f"\n🔍 https://github.com/{GITHUB_OWNER}/{GITHUB_REPO}/security/code-scanning")
        return True
    else:
        print(f"❌ Error: {r.status_code}\n{r.text}")
        return False


def main():
    print("=" * 70)
    print("🔒 GETIR SECURITY - Professional Pentest Report")
    print("=" * 70)
    print()

    for i in JIRA_ISSUES:
        e = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪"}[i["severity"]]
        print(f"   {e} {i['key']} - {i['summary']}")

    print(f"\n🔄 Creating professional SARIF...")
    sarif = create_sarif(JIRA_ISSUES)

    with open("sarif.template", "w") as f:
        json.dump(sarif, f, indent=2)
    print("   💾 Saved locally")

    print()
    if upload(sarif):
        print("\n✅ Done! Check GitHub Security tab")
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
