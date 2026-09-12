#!/usr/bin/env python3
import os, json, base64, hashlib, re
from datetime import datetime, timezone
from flask import Flask, request, jsonify
import requests
from bs4 import BeautifulSoup
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

app=Flask(__name__)
NORMALIZER_VERSION="KM-JRA-OFFICIAL-NORMALIZER-v0.2-CANDIDATE"

def cjson(x):
    return json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=False)
def sha(b): return hashlib.sha256(b).hexdigest()
def clean(s): return re.sub(r"\s+"," ",s or "").strip()

def load_key():
    raw=base64.b64decode(os.environ["WITNESS_PRIVATE_KEY_B64"])
    if len(raw)!=32: raise RuntimeError("BAD_ED25519_PRIVATE_KEY_LENGTH")
    return Ed25519PrivateKey.from_private_bytes(raw)

def pub_b64():
    key=load_key()
    raw=key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return base64.b64encode(raw).decode()

def normalize(raw_html:bytes, source_url:str, race_id:str):
    soup=BeautifulSoup(raw_html,"html.parser")
    text=clean(soup.get_text(" "))
    m=re.search(r"出馬表\s*(\d{4})年(\d{1,2})月(\d{1,2})日.*?(\d+)回(中山|阪神)(\d+)日\s*(\d+)レース",text)
    if not m: raise ValueError("RACE_HEADER_NOT_FOUND")
    y,mo,da,meeting_no,venue,day_no,race_no=m.groups()
    tm=re.search(r"発走時刻[:：]?\s*(\d{1,2})時(\d{2})分",text)
    if not tm: raise ValueError("START_TIME_NOT_FOUND")
    cm=re.search(r"コース[:：]\s*([0-9,]+)メートル（([^）]+)）",text)
    if not cm: raise ValueError("COURSE_NOT_FOUND")
    date=f"{int(y):04d}-{int(mo):02d}-{int(da):02d}"
    hh,mm=tm.groups()

    runners=[]
    seen=set()
    # JRA desktop table: the row text contains horse number/name and later "55.0 kg jockey".
    for tr in soup.find_all("tr"):
        cells=[clean(x.get_text(" ")) for x in tr.find_all(["th","td"])]
        t=" ".join(x for x in cells if x)
        if not t: continue
        nm=re.search(r"(?:^|\s)(\d{1,2})\s+([^\s]+).*?(\d{2}(?:\.\d)?)\s*kg\s+([^\d|]+?)(?=\s+\d{4}年|$)",t)
        if not nm: continue
        no=int(nm.group(1))
        if not (1<=no<=18) or no in seen: continue
        name=clean(nm.group(2)); weight=float(nm.group(3)); jockey=clean(nm.group(4))
        if len(name)<2 or name in {"馬名","馬番"}: continue
        seen.add(no)
        runners.append({"horse_no":no,"horse_name":name,"carried_weight_kg":weight,"jockey":jockey})
    runners=sorted(runners,key=lambda x:x["horse_no"])
    if len(runners)<2: raise ValueError("RUNNER_UNIVERSE_PARSE_INCOMPLETE")
    payload={
        "normalizer_version":NORMALIZER_VERSION,
        "capture_kind":"OFFICIAL_RACE_RUNNER_UNIVERSE",
        "completeness_profile":"FULL_RUNNER_UNIVERSE",
        "race_id":race_id,
        "meeting":f"{meeting_no}回{venue}{day_no}日",
        "venue":venue,
        "race_no":int(race_no),
        "race_date":date,
        "scheduled_start_at":f"{date}T{int(hh):02d}:{int(mm):02d}:00+09:00",
        "course_distance_m":int(cm.group(1).replace(",","")),
        "course_surface_detail":cm.group(2),
        "source_locator":source_url,
        "source_provider_id":"JRA",
        "runners":runners,
        "runner_count":len(runners),
    }
    return payload

@app.get("/health")
def health():
    return jsonify({
        "status":"ok",
        "service":"KM-JRA-Independent-Witness",
        "normalizer_version":NORMALIZER_VERSION,
        "trust_domain_id":os.environ.get("WITNESS_TRUST_DOMAIN_ID"),
        "operational_allowed":os.environ.get("WITNESS_OPERATIONAL_ALLOWED","false").lower()=="true"
    })

@app.get("/public-key")
def public_key():
    return jsonify({
        "signer_key_id":os.environ["WITNESS_SIGNER_KEY_ID"],
        "trust_domain_id":os.environ["WITNESS_TRUST_DOMAIN_ID"],
        "public_key_b64":pub_b64(),
        "normalizer_version":NORMALIZER_VERSION,
        "operational_allowed":os.environ.get("WITNESS_OPERATIONAL_ALLOWED","false").lower()=="true"
    })

@app.post("/capture")
def capture():
    req=request.get_json(force=True)
    source_url=req["source_url"]; race_id=req["race_id"]
    if "jra.go.jp/" not in source_url:
        return jsonify({"status":"error","error":"SOURCE_NOT_JRA"}),400
    r=requests.get(source_url,timeout=20,headers={"User-Agent":"KM-JRA-Independent-Witness/0.2"})
    r.raise_for_status()
    raw=r.content
    payload=normalize(raw,source_url,race_id)
    captured_at=datetime.now(timezone.utc).astimezone().isoformat()
    payload["captured_at"]=captured_at
    ph=sha(cjson(payload).encode())
    receipt={
        "receipt_kind":"OFFICIAL_SOURCE_NORMALIZED_CAPTURE",
        "evidence_class":"E2_WITNESS_CANDIDATE",
        "source_provider_id":"JRA",
        "signer_key_id":os.environ["WITNESS_SIGNER_KEY_ID"],
        "trust_domain_id":os.environ["WITNESS_TRUST_DOMAIN_ID"],
        "capture_id":f"WITNESS-{race_id}-{captured_at}",
        "race_id":race_id,
        "captured_at":captured_at,
        "source_locator":source_url,
        "normalizer_version":payload["normalizer_version"],
        "completeness_profile":payload["completeness_profile"],
        "payload_sha256":ph,
        "raw_source_sha256":sha(raw),
        "runner_count":payload["runner_count"]
    }
    key=load_key()
    receipt["signature_b64"]=base64.b64encode(key.sign(cjson(receipt).encode())).decode()
    return jsonify({"status":"ok","payload":payload,"receipt":receipt,
                    "diagnostics":{"raw_bytes":len(raw),"runner_count":payload["runner_count"]}})
if __name__=="__main__":
    app.run(host="0.0.0.0",port=int(os.environ.get("PORT","8080")))
