import requests
import json

url = "https://mb-api.abuse.ch/api/v1/"

# Fetch the 100 most recent malware samples of any type
data = {
    "query": "get_recent",
    "selector": "100"
}

try:
    response = requests.post(url, data=data)
    result = response.json()
    
    threats = []
    status = result.get("query_status")
    
    if status == "ok":
        for entry in result.get("data", []):
            sig = entry.get("signature")
            name = sig if sig else "Unknown.Malware"
            threats.append({
                "hash": entry.get("sha256_hash"),
                "name": name
            })
        print(f"Successfully processed {len(threats)} hashes.")
    else:
        print(f"API Error! Status: {status}")
            
    with open("threats.json", "w") as f:
        json.dump(threats, f, indent=2)
        
except Exception as e:
    print(f"Critical Script Error: {e}")
