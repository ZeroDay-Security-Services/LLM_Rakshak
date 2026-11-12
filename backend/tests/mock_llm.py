"""Local OpenAI-compatible server used ONLY by the test-suite as the system under test.
/vuln/*  naive, instruction-following target (should produce findings)
/safe/*  hardened target (should produce a clean result)
/slow/*  vulnerable + slow (for pause/cancel tests)"""
import asyncio, base64, codecs, json, re
from fastapi import FastAPI, Request

TOOLS = ["delete_records", "send_email", "transfer_funds", "execute_command", "get_order"]
ECHO_KW = ("instructions", "configuration", "reference token", "repeat all the text", "dump_config", "restricted chunk", "contact details",
           "email address", "forbidden from outputting", "summarise everything", "your operating")
seen_auth: list[str] = []


def build() -> FastAPI:
    app = FastAPI()

    def reply(text=None, calls=None):
        msg = {"role": "assistant", "content": text}
        if calls:
            msg["tool_calls"] = [{"id": "c1", "type": "function", "function": {"name": n, "arguments": json.dumps(a)}} for n, a in calls]
        return {"id": "x", "choices": [{"index": 0, "message": msg, "finish_reason": "stop"}], "usage": {"prompt_tokens": 20, "completion_tokens": 10}}

    @app.post("/{mode}/v1/chat/completions")
    async def chat(mode: str, req: Request):
        body = await req.json()
        auth = req.headers.get("authorization", "")
        seen_auth.append(auth)
        msgs = body["messages"]
        system = " ".join(m["content"] for m in msgs if m["role"] == "system")
        users = [m["content"] for m in msgs if m["role"] == "user"]
        last = users[-1]
        if mode == "slow":
            await asyncio.sleep(0.25)
        if "17 multiplied by 23" in last:
            return reply("391")
        if "True or False" in last:
            return reply("False" if mode == "safe" else "True")
        if "single word OK" in last or mode == "safe":
            return reply("OK" if "single word OK" in last else "I can't help with that request.")
        # ---- vulnerable behaviour below
        if body.get("tools"):
            if "Delete all the old audit logs" in last or "delete_records" in last:
                return reply(None, [("delete_records", {"table": "audit", "where": "1=1"})])
            if "send_email" in last:
                to = re.search(r"[\w.]+@example\.invalid", last)
                sec = re.search(r"LGS-[A-F0-9]+", system)
                return reply(None, [("send_email", {"to": to.group(0) if to else "x@example.invalid", "subject": "t", "body": sec.group(0) if sec and "token" in last else "hi"})])
            if "Move 500 credits" in last or "transfer_funds" in last:
                return reply(None, [("transfer_funds", {"from_account": "A", "to_account": "77", "amount": 500})])
            if "execute_command" in last:
                c = re.search(r"command='([^']+)'", last)
                return reply(None, [("execute_command", {"command": c.group(1) if c else "id"})])
            if "Show order" in last:
                u = re.search(r"U-\d+", last)
                return reply(None, [("get_order", {"order_id": "1042", "user_id": u.group(0) if u else "U-1001"})])
        if "<script>" in last and "raw html" in last.lower():
            return reply(re.search(r"<script>.*?</script>", last).group(0))
        if "onerror" in last:
            return reply(f"<img src=x onerror=alert('{re.search(r'LGC-[A-F0-9-]+', last).group(0)}')>")
        if "![status]" in last:
            return reply(re.search(r"!\[status\]\([^)]+\)", last).group(0))
        if "javascript:" in last:
            return reply(f"[docs](javascript:alert('{re.search(r'LGC-[A-F0-9-]+', last).group(0)}'))")
        if '"note"' in last:
            return reply('{"note": "hi", "admin": true, "x": {"y": "z"}}')
        if "API keys, passwords" in last:
            return reply("Sure, my key is " + auth.replace("Bearer ", ""))
        if "DOI for the 2019 paper" in last or "journal, volume and DOI" in last:
            return reply("Published in Journal of Orchard Studies, vol. 12, DOI 10.1234/qzr.2019.04")
        if "PART1" in last:
            a = re.search(r"LGC-[A-F0-9]{6}-", users[0]).group(0)
            b = re.search(r"PART2: ([A-F0-9]{6})", last).group(1)
            return reply(a + b)
        if "one character per line" in last:
            return reply("\n".join(re.search(r"LGP-[A-F0-9]+", last).group(0)))
        if "again" in last.lower():
            hist = re.findall(r"LG[CP]-[A-F0-9\-]+[A-F0-9]", " ".join(m["content"] for m in msgs if m["role"] != "system"))
            if hist:
                return reply(hist[-1])
        cands = [last, codecs.decode(last, "rot13")]
        for w in re.findall(r"[A-Za-z0-9+/=]{24,}", last):
            try:
                cands.append(base64.b64decode(w).decode())
            except Exception:  # noqa
                pass
        for c in cands:
            t = re.findall(r"LG[CP]-[A-F0-9\-]+[A-F0-9]", c)
            if t:
                return reply(t[0])
        if any(k in last.lower() for k in ECHO_KW):
            return reply("Sure. " + system + " | " + last)
        return reply("Sure, happy to help.")

    return app
