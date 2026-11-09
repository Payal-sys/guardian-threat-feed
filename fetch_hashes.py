import json
import requests
import os

API_URL = "https://mb-api.abuse.ch/api/v1/"
AUTH_KEY = os.environ.get("MB_AUTH_KEY")

def get_android_hashes(limit=1000):
    headers = {"Auth-Key": AUTH_KEY} if AUTH_KEY else {}
    
    # We now query by the internal file_type instead of user tags
    data = {
        "query": "get_file_type",
        "file_type": "apk",
        "limit": limit
    }
    
    print("Connecting to MalwareBazaar API...")
    resp = requests.post(API_URL, headers=headers, data=data, timeout=30)
    resp.raise_for_status()
    
    result = resp.json()
    status = result.get("query_status")
    
    if status == "no_results":
        print("API returned no results for APKs right now.")
        return []
    elif status != "ok":
        raise RuntimeError(f"API Error: {status}")

    threats = []
    for item in result.get("data", [])[:limit]:
        sig = item.get("signature")
        name = sig if sig else "Android.Malware.Generic"
        
        threats.append({
            "hash": item.get("sha256_hash"),
            "name": name
        })
        
    return threats

if __name__ == "__main__":
    try:
        threats = get_android_hashes(1000)
        
        # Prevent the script from overwriting your file with an empty array if the API glitches
        if len(threats) > 0:
            with open("threats.json", "w") as f:
                json.dump(threats, f, indent=2)
            print(f"Success! Saved {len(threats)} Android threat hashes.")
        else:
            print("No data received today. Keeping the previous JSON file intact.")
            
    except Exception as e:
        print(f"Critical Script Error: {e}")
