import time
import requests

def check_virustotal(url: str, api_key: str) -> dict:
    if not api_key:
        return {
            "available": False,
            "error": "VirusTotal API key not set. Add VT_API_KEY environment variable.",
            "setup": "Get free key at https://www.virustotal.com"
        }
    headers = {"x-apikey": api_key}
    try:
        resp = requests.post("https://www.virustotal.com/api/v3/urls",
                             headers=headers, data={"url": url}, timeout=15)
        resp.raise_for_status()
        analysis_id = resp.json()["data"]["id"]

        for _ in range(4):
            time.sleep(4)
            r = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                             headers=headers, timeout=15)
            r.raise_for_status()
            data   = r.json()
            status = data["data"]["attributes"]["status"]
            if status == "completed":
                stats   = data["data"]["attributes"]["stats"]
                engines = data["data"]["attributes"].get("results", {})
                flagged = [{"engine": k, "result": v["result"], "category": v.get("category","")}
                           for k, v in engines.items()
                           if v.get("category") in ("malicious","suspicious")][:10]
                total = sum(stats.values()) or 1
                return {
                    "available": True, "status": "completed",
                    "malicious":  stats.get("malicious",  0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless":   stats.get("harmless",   0),
                    "undetected": stats.get("undetected", 0),
                    "total_engines": total,
                    "detection_rate": round((stats.get("malicious", 0) / total) * 100, 1),
                    "flagged_by": flagged,
                    "vt_link": f"https://www.virustotal.com/gui/url/{analysis_id}",
                }

        return {"available": True, "status": "timeout", "error": "Analysis timed out. Try again."}

    except requests.HTTPError as e:
        if e.response is not None and e.response.status_code == 429:
            return {"available": False, "error": "Rate limit hit. Wait 60 seconds."}
        return {"available": False, "error": f"HTTP error: {str(e)}"}
    except Exception as e:
        return {"available": False, "error": f"Error: {str(e)}"}