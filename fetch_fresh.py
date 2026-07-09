import urllib.request
import base64
import json
import os
import sys
from Crypto.Cipher import AES

sys.stdout.reconfigure(encoding="utf-8")

# Load Config
config_path = "app_control.json"
if not os.path.exists(config_path):
    print("Error: app_control.json not found.")
    sys.exit(1)

with open(config_path, "r", encoding="utf-8") as f:
    config = json.load(f)

active_source = config.get("active_source", "crexify")
profile = config["sources"][active_source]
api_url = profile["api_url"]
keys = profile["keys"]

out_dir = "decrypted_output"
os.makedirs(out_dir, exist_ok=True)

github_user = os.environ.get("GITHUB_REPOSITORY_OWNER", "mdjamsad9")
github_repo = os.environ.get("GITHUB_REPOSITORY", "mdjamsad9/apiv2").split("/")[-1]
pages_base = f"https://{github_user}.github.io/{github_repo}/decrypted_output"

print(f"API Source: {api_url}")
print(f"Pages Base: {pages_base}")

def decrypt_aes(ciphertext, key, iv):
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        dec = cipher.decrypt(ciphertext)
        pad_len = dec[-1]
        if 1 <= pad_len <= 16 and all(x == pad_len for x in dec[-pad_len:]):
            dec = dec[:-pad_len]
        return dec
    except Exception as e:
        print(f"  AES Error: {e}")
        return None

def make_request(url, timeout=20):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.read()
    except Exception as e:
        print(f"  Request failed for {url}: {e}")
        return None

def decrypt_file(raw_bytes, label="file"):
    if not raw_bytes:
        return None
    try:
        cleaned = "".join(raw_bytes.decode("utf-8").strip().split())
        while len(cleaned) % 4 != 0:
            cleaned += "="
        ciphertext = base64.b64decode(cleaned)
        print(f"  [{label}] ciphertext: {len(ciphertext)} bytes")
    except Exception as e:
        print(f"  [{label}] Base64 decode error: {e}")
        return None

    key_b = keys["Crexify_SetB"]["aes_key"].encode("utf-8")
    iv_b  = keys["Crexify_SetB"]["aes_iv"].encode("utf-8")
    result = decrypt_aes(ciphertext, key_b, iv_b)
    if result and result[0:1] in [b"{", b"["]:
        print(f"  [{label}] SetB OK")
        return result

    key_a = keys["Crexify_SetA"]["aes_key"].encode("utf-8")
    iv_a  = keys["Crexify_SetA"]["aes_iv"].encode("utf-8")
    result = decrypt_aes(ciphertext, key_a, iv_a)
    if result and result[0:1] in [b"{", b"["]:
        print(f"  [{label}] SetA OK")
        return result

    print(f"  [{label}] WARNING: no valid JSON start with either key")
    return decrypt_aes(ciphertext, key_b, iv_b)

success_count = 0

# 1. app.json
print("\n=== app.txt ===")
raw = make_request(f"{api_url}app.txt")
dec = decrypt_file(raw, "app.txt")
if dec:
    try:
        app_data = json.loads(dec.decode("utf-8", errors="ignore"))
        def inject_url(obj):
            if isinstance(obj, list):
                for item in obj:
                    inject_url(item)
            elif isinstance(obj, dict):
                obj["api_url"] = pages_base + "/"
                obj["new_api"] = pages_base + "/"
                if "web_url" in obj:
                    obj["web_url"] = pages_base + "/"
        inject_url(app_data)
        with open(os.path.join(out_dir, "app.json"), "w", encoding="utf-8") as f:
            json.dump(app_data, f, indent=2, ensure_ascii=False)
        print("-> app.json saved")
        success_count += 1
    except Exception as e:
        print(f"-> app.json parse error: {e}")
else:
    print("-> app.txt failed")

# 2. event_cats.json
print("\n=== event_cats.txt ===")
raw = make_request(f"{api_url}event_cats.txt")
dec = decrypt_file(raw, "event_cats.txt")
if dec:
    try:
        data = json.loads(dec.decode("utf-8", errors="ignore"))
        with open(os.path.join(out_dir, "event_cats.json"), "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print("-> event_cats.json saved")
        success_count += 1
    except Exception as e:
        print(f"-> parse error: {e}, preview: {dec[:80]}")
else:
    print("-> event_cats.txt failed")

# 3. categories.json
print("\n=== categories.txt ===")
raw = make_request(f"{api_url}categories.txt")
dec = decrypt_file(raw, "categories.txt")
raw_channels = []
if dec:
    try:
        cats = json.loads(dec.decode("utf-8", errors="ignore"))
        if isinstance(cats, list):
            for cat in cats:
                if isinstance(cat, dict):
                    ch = cat.get("channels", [])
                    if isinstance(ch, list):
                        raw_channels.extend(ch)
        def update_ch_links(obj):
            if isinstance(obj, list):
                for item in obj:
                    update_ch_links(item)
            elif isinstance(obj, dict):
                lnk = obj.get("links", "")
                if lnk and lnk.startswith("channels/"):
                    obj["links"] = f"{pages_base}/{lnk}"
        update_ch_links(cats)
        with open(os.path.join(out_dir, "categories.json"), "w", encoding="utf-8") as f:
            json.dump(cats, f, indent=2, ensure_ascii=False)
        print(f"-> categories.json saved ({len(raw_channels)} channels found)")
        success_count += 1
    except Exception as e:
        print(f"-> parse error: {e}, preview: {dec[:80]}")
else:
    print("-> categories.txt failed")

# 4. events.json
print("\n=== events.txt ===")
raw = make_request(f"{api_url}events.txt")
dec = decrypt_file(raw, "events.txt")
events_list = []
if dec:
    try:
        data = json.loads(dec.decode("utf-8", errors="ignore"))
        events_list = data if isinstance(data, list) else []
        for event in events_list:
            if isinstance(event, dict):
                lnk = event.get("links", "")
                if lnk and lnk.startswith("pro/"):
                    event["links"] = f"{pages_base}/{lnk}"
        with open(os.path.join(out_dir, "events.json"), "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"-> events.json saved ({len(events_list)} events)")
        success_count += 1
    except Exception as e:
        print(f"-> parse error: {e}, preview: {dec[:80]}")
else:
    print("-> events.txt failed")

# 5. Pro files
pro_dir = os.path.join(out_dir, "pro")
os.makedirs(pro_dir, exist_ok=True)
print(f"\n=== Pro stream files ({len(events_list)} events) ===")
pro_saved = 0
for event in events_list:
    if not isinstance(event, dict):
        continue
    lnk = event.get("links", "")
    if "pro/" in lnk:
        filename = lnk.split("pro/")[-1]
        if not filename:
            continue
        raw = make_request(f"{api_url}pro/{filename}")
        dec = decrypt_file(raw, filename[:25])
        if dec:
            try:
                out_path = os.path.join(pro_dir, filename)
                try:
                    pro_data = json.loads(dec.decode("utf-8", errors="ignore"))
                    with open(out_path, "w", encoding="utf-8") as f:
                        json.dump(pro_data, f, indent=2, ensure_ascii=False)
                except Exception:
                    with open(out_path, "w", encoding="utf-8") as f:
                        f.write(dec.decode("utf-8", errors="ignore"))
                pro_saved += 1
            except Exception as e:
                print(f"    Save error: {e}")
print(f"-> {pro_saved}/{len(events_list)} pro files saved")

# 6. Channel files
ch_dir = os.path.join(out_dir, "channels")
os.makedirs(ch_dir, exist_ok=True)
print(f"\n=== Channel files ({len(raw_channels)} channels) ===")
ch_saved = 0
for ch in raw_channels:
    if not isinstance(ch, dict):
        continue
    lnk = ch.get("links", "")
    if "channels/" in lnk:
        filename = lnk.split("channels/")[-1]
        if not filename:
            continue
        raw = make_request(f"{api_url}channels/{filename}")
        dec = decrypt_file(raw, filename[:25])
        if dec:
            try:
                out_path = os.path.join(ch_dir, filename)
                try:
                    ch_data = json.loads(dec.decode("utf-8", errors="ignore"))
                    with open(out_path, "w", encoding="utf-8") as f:
                        json.dump(ch_data, f, indent=2, ensure_ascii=False)
                except Exception:
                    with open(out_path, "w", encoding="utf-8") as f:
                        f.write(dec.decode("utf-8", errors="ignore"))
                ch_saved += 1
            except Exception as e:
                print(f"    Save error: {e}")
print(f"-> {ch_saved}/{len(raw_channels)} channel files saved")

# Summary
print(f"\n{'='*50}")
print(f"SUMMARY: {success_count}/4 main | {pro_saved} pro | {ch_saved} channels")
if success_count == 0:
    print("ERROR: No main files decrypted!")
    sys.exit(1)
print("Done!")
