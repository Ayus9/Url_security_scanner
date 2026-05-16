import time
import requests

def run_zap_scan(url: str, zap_base: str, api_key: str) -> dict:
    params = {"apikey": api_key, "zapapiformat": "JSON"}

    def zap(endpoint, extra={}):
        r = requests.get(f"{zap_base}/JSON/{endpoint}", params={**params, **extra}, timeout=20)
        r.raise_for_status()
        return r.json()

    try:
        version = zap("core/view/version/").get("version", "unknown")

        spider_id = zap("spider/action/scan/", {"url": url, "maxChildren": 5, "recurse": "true"}).get("scan","0")
        for _ in range(10):
            time.sleep(3)
            if int(zap("spider/view/status/", {"scanId": spider_id}).get("status", 0)) >= 100:
                break

        scan_id = zap("ascan/action/scan/", {"url": url, "recurse": "false"}).get("scan","0")
        for _ in range(30):
            time.sleep(3)
            if int(zap("ascan/view/status/", {"scanId": scan_id}).get("status", 0)) >= 100:
                break

        raw = zap("core/view/alerts/", {"baseurl": url, "start": "0", "count": "100"}).get("alerts", [])
        counts = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        alerts = []
        for a in raw:
            risk = a.get("risk", "Informational")
            counts[risk] = counts.get(risk, 0) + 1
            alerts.append({
                "name":        a.get("name", "Unknown"),
                "risk":        risk,
                "confidence":  a.get("confidence", ""),
                "description": a.get("description", "")[:300],
                "solution":    a.get("solution", "")[:300],
                "evidence":    a.get("evidence", "")[:100],
                "cweid":       a.get("cweid", ""),
                "wascid":      a.get("wascid", ""),
            })
        alerts.sort(key=lambda x: {"High":0,"Medium":1,"Low":2,"Informational":3}.get(x["risk"],4))
        return {"available": True, "zap_version": version,
                "total_alerts": len(alerts), "risk_counts": counts, "alerts": alerts}

    except requests.ConnectionError:
        return {"available": False,
                "error": "ZAP not running. Start ZAP on port 8080 first.",
                "setup": "./zap.sh -daemon -port 8080 -config api.key=changeme"}
    except Exception as e:
        return {"available": False, "error": f"ZAP error: {str(e)}"}