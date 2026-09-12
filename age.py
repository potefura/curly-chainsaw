#!/usr/bin/env python3
import sys, json, uuid, time, random, string
from pathlib import Path
from curl_cffi import requests

# ── ヘルパー ──────────────────────────────────────────────

def gen_uid():
    return f"bplus-{uuid.uuid4().hex}"

def gen_trace():
    return uuid.uuid4().hex.replace("-", "")

def gen_baggage(tid):
    r = round(random.uniform(0.01, 0.99), 16)
    return (f"sentry-environment=production,"
            f"sentry-public_key=bf5c7dd876d52371d5693e7cae08a75f,"
            f"sentry-trace_id={tid},"
            f"sentry-transaction=/face-shape-detector/[type],"
            f"sentry-sampled=true,sentry-sample_rand={r},sentry-sample_rate=1")

def build_cookies():
    now     = int(time.time())
    first   = now - random.randint(86400, 86400 * 7)
    ga_cid  = random.randint(1_000_000_000, 1_999_999_999)
    sm_id   = f"{uuid.uuid4().hex[:16]}-{uuid.uuid4().hex[:8]}-{random.randint(100000,999999)}-280800-{uuid.uuid4().hex[:16]}"
    tt_rand = ''.join(random.choices(string.ascii_letters + string.digits, k=20))
    now_ms  = now * 1000
    return {
        "_ga":               f"GA1.1.{ga_cid}.{first}",
        "_gcl_au":           f"1.1.{random.randint(100_000_000,999_999_999)}.{first}",
        "_fbp":              f"fb.1.{now_ms}.{random.randint(10**15,10**16-1)}",
        "_tt_enable_cookie": "1",
        "_ttp":              f"{''.join(random.choices(string.ascii_uppercase+string.digits+'_.',k=28))}.tt.1.{now_ms}",
        "_clck":             f"{''.join(random.choices(string.ascii_lowercase+string.digits,k=7))}%5E2%5E{''.join(random.choices(string.ascii_lowercase,k=3))}%5E0%5E2446",
        "_sm":               sm_id,
        "meitustat":         json.dumps({"wgid": sm_id}, separators=(',',':')),
        "ttcsid":            f"{now_ms}::{tt_rand}.1.{now_ms-random.randint(1000,60000)}.0::0.100000.100000::100000.4.100.500::50000.20.0",
        "_ga_HLHTM37DYD":    f"GS2.1.s{first}$o2$g1$t{now}$j30$l0$h0",
        "_clsk":             f"{''.join(random.choices(string.ascii_lowercase+string.digits,k=7))}%5E{now_ms}%5E5%5E1%5Er.clarity.ms%2Fcollect",
    }

GENDER_MAP = {0: "male", 1: "female"}

# ── メインクラス ──────────────────────────────────────────

class BeautyPlusDetector:
    UA      = ("Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/127.0.0.0 Mobile Safari/537.36")
    SEC_UA  = ('"Chromium";v="127", "Not)A;Brand";v="99", '
               '"Microsoft Edge Simulate";v="127", "Lemur";v="127"')

    def __init__(self):
        self.uid     = gen_uid()
        self.session = requests.Session(impersonate="chrome131_android")
        for k, v in build_cookies().items():
            self.session.cookies.set(k, v, domain=".beautyplus.com", path="/")

    def _h(self, referer):
        tid = gen_trace()
        return {
            "accept":             "application/json, text/plain, */*",
            "accept-language":    "ja-JP",
            "content-type":       "application/json",
            "origin":             "https://www.beautyplus.com",
            "referer":            referer,
            "user-agent":         self.UA,
            "sec-ch-ua":          self.SEC_UA,
            "sec-ch-ua-mobile":   "?1",
            "sec-ch-ua-platform": '"Android"',
            "sec-fetch-dest":     "empty",
            "sec-fetch-mode":     "cors",
            "sec-fetch-site":     "same-origin",
            "priority":           "u=1, i",
            "sentry-trace":       f"{tid}-{uuid.uuid4().hex[:16]}-1",
            "baggage":            gen_baggage(tid),
            "x-anonymous-uid":    self.uid,
            "x-locale":           "ja",
            "x-tenant":           "bplus",
        }

    def _get_policy(self, suffix):
        r = self.session.get(
            "https://strategy.pixocial.com/upload/policy",
            params={"app": "BeautyPlusWeb", "suffix": suffix, "type": "tmp-photo"},
            headers={
                "accept": "*/*", "accept-language": "ja-JP",
                "origin": "https://www.beautyplus.com",
                "referer": "https://www.beautyplus.com/",
                "user-agent": self.UA, "sec-ch-ua": self.SEC_UA,
                "sec-ch-ua-mobile": "?1", "sec-ch-ua-platform": '"Android"',
                "sec-fetch-dest": "empty", "sec-fetch-mode": "cors",
                "sec-fetch-site": "cross-site",
            },
            timeout=15,
        )
        r.raise_for_status()
        return r.json()

    def upload(self, path):
        p = Path(path)
        suffix = p.suffix.lstrip(".").lower() or "jpg"
        raw = self._get_policy(suffix)
        oss = raw[0]["oss"] if isinstance(raw, list) else raw.get("oss", raw)

        import oss2
        creds  = oss["credentials"]
        auth   = oss2.StsAuth(creds["access_key"], creds["secret_key"], creds["session_token"])
        bucket = oss2.Bucket(auth, oss["url"], oss["bucket"], connect_timeout=30)
        mime   = "image/jpeg" if suffix in ("jpg","jpeg") else f"image/{suffix}"
        result = bucket.put_object(oss["key"], p.read_bytes(), headers={"Content-Type": mime})
        if result.status != 200:
            raise RuntimeError(f"OSS PUT failed: {result.status}")
        return oss["data"]

    def check_nsfw(self, url):
        r = self.session.post(
            "https://www.beautyplus.com/core-api/v1/nsfw/check",
            json={"imageUrl": url},
            headers=self._h("https://www.beautyplus.com/ja/face-shape-detector/how-old-do-i-look"),
            timeout=15,
        )
        if r.status_code == 429:
            raise RuntimeError("RATELIMIT")
        r.raise_for_status()
        return r.json()

    def face_task(self, url):
        r = self.session.post(
            "https://www.beautyplus.com/core-api/v1/face-detector/task",
            json={"sourceUrl": url},
            headers=self._h("https://www.beautyplus.com/ja/face-shape-detector/result?rp=0a0ot32r&type=how-old-do-i-look"),
            timeout=20,
        )
        if r.status_code == 429:
            raise RuntimeError("RATELIMIT")
        r.raise_for_status()
        return r.json()

    def analyze(self, image_url):
        nsfw = self.check_nsfw(image_url)
        if nsfw.get("nsfw"):
            raise RuntimeError("NSFW")
        task  = self.face_task(image_url)
        faces = task.get("faceAttributes", [])
        if not faces:
            raise RuntimeError("NO_FACE")
        ex = faces[0].get("faceExtraInfo", {})
        age    = ex.get("age")
        gender = GENDER_MAP.get(ex.get("gender"), "unknown")
        return age, gender

# ── CLI ──────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("失敗しました")
        sys.exit(1)
    try:
        d = BeautyPlusDetector()
        if sys.argv[1] == "--url" and len(sys.argv) > 2:
            url = sys.argv[2]
        else:
            url = d.upload(sys.argv[1])
        age, gender = d.analyze(url)
        print(f"{age},{gender}")
    except RuntimeError as e:
        if "RATELIMIT" in str(e):
            print("Ratelimit")
        else:
            print("失敗しました")
        sys.exit(1)
    except Exception:
        print("失敗しました")
        sys.exit(1)

if __name__ == "__main__":
    main()
