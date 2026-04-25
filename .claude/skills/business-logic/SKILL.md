---
name: business-logic
description: Business Logic Bugs — multi-step flow manipulation, checkout/pricing abuse, subscription bypass, coupon stacking, referral fraud, state machine attacks (skip/repeat/reverse steps), unreleased feature access, and "what if I..." mindset testing. Use when the app has any multi-step flow, pricing logic, feature gating, or user-controlled state that automated tools cannot reason about.
---

# Business Logic Bugs (INDEX — Parameter Logic Bugs / Flow Bypass)

This skill is mindset-heavy. The core technique is asking "what if I...?" questions and mapping every multi-step flow as a state machine, then testing every forbidden transition. Read top to bottom on first invocation.

---

## 1. Triggers — when this skill applies

Business logic bugs apply to almost every non-trivial web application. Specifically prioritize when:

- The app has a checkout / purchase / payment flow
- The app has subscription tiers with feature gating (free vs paid vs enterprise)
- The app has multi-step onboarding, verification, or upgrade flows
- The app has coupon codes, referral programs, gift cards, or loyalty points
- The app has time-gated features ("available from X date", "trial expires Y")
- The app has approval workflows (request → review → approve)
- The app has any form of inventory or quantity constraints
- IDs in URLs look guessable or sequential (access partially-completed other users' flows)
- A feature is visible in the UI but disabled/greyed-out (click blocking vs server-side check)
- The app sends the price, discount, or quantity from the client and uses it server-side without re-verification

---

---

## 3. The "What if I...?" checklist

For every flow or feature, ask all of the following:

### 3.1 Multi-step flow attacks
- [ ] What if I **skip step N** entirely and jump to step N+2?
- [ ] What if I **repeat step N** twice (double-submit, refresh, back-button)?
- [ ] What if I **do the steps in reverse order** (complete before paying, verify before submitting)?
- [ ] What if I **cancel mid-flow** then check whether partial state was committed?
- [ ] What if I **start the flow twice in parallel** (race condition + logic)?
- [ ] What if I **replay an old step** after completing the flow?
- [ ] What if I **access the final step URL directly** without completing prior steps?

### 3.2 Pricing and payment
- [ ] What if I **add the item at discounted price, then change quantity** after price is committed?
- [ ] What if I **modify the price in the request** (if the client sends price server-side)?
- [ ] What if I **apply multiple coupons** (stack them — coupon stacking attack)?
- [ ] What if I **apply a coupon after checkout** is initiated?
- [ ] What if I **set quantity to zero** and still check out?
- [ ] What if I **set quantity negative** (turns order into credit)?
- [ ] What if I **remove the payment step** from the flow?
- [ ] What if I **change the currency** mid-flow?

### 3.3 Feature access
- [ ] What if I **navigate directly to the premium feature URL** without subscribing?
- [ ] What if I **start a trial, cancel, then re-start** (infinite trial)?
- [ ] What if I **access an admin-only endpoint** as a regular user by guessing the URL?
- [ ] What if I **access a feature that's "coming soon"** by constructing the productId request?
- [ ] What if I **access another user's in-progress flow** by guessing their ID or token?
- [ ] What if I **access my own flow from a different account** (cross-account state access)?

### 3.4 Referral and reward abuse
- [ ] What if I **refer myself** (create a second account)?
- [ ] What if I **refer the same person twice** before they complete registration?
- [ ] What if I **self-refer with a different email** that resolves to the same inbox (`user+tag@email.com`)?
- [ ] What if I **reverse a referral** after the credit is issued?
- [ ] What if I **claim a referral reward without completing the required action**?

### 3.5 Account and session
- [ ] What if I **downgrade my subscription mid-billing period** — is access revoked immediately or at end of period? Can I re-upgrade for free?
- [ ] What if I **delete my account** and then re-register with the same email?
- [ ] What if I **change my email to an admin email** mid-flow?
- [ ] What if I **log out between steps** of a sensitive multi-step flow?

---

## 4. State machine mapping

Before testing, draw the intended flow as a state machine:

```
[Start] → [Add to cart] → [Enter address] → [Apply coupon] → [Pay] → [Confirmed]
```

For each state, identify:
1. What HTTP request transitions from this state to the next?
2. Does the server validate that the prior state was reached?
3. What happens if I send the transition request from the wrong state?

**Example — unreleased iPhone from notes:**
```
[Browse] → [Product page - "Coming Soon" UI] → [Add to cart (BLOCKED by JS)] → [Checkout]
```
Attack: bypass step 2 UI block by directly sending the add-to-cart API call with the unreleased `productId`. Server did not re-validate product availability.

**Draw the full state machine for any complex flow before testing.** States and transitions you map become your attack surface.

---

## 5. Detection methodology

### 5.1 Map all flows

For every app feature:
1. Browse the app as a real user, intercept all requests in Burp
2. Note every multi-step sequence: what requests happen, what parameters are sent
3. Identify which parameters are set by the server vs submitted by the client
4. Check if the flow has state stored server-side (session, DB) or client-side (hidden fields, localStorage, cookies)

### 5.2 Find client-side trusted values

These are high-priority targets:
```
price=19.99           (client sets price, server uses it)
discount=50           (client claims discount, server applies it)
productId=9999        (client picks ID, server doesn't validate availability)
step=3                (client claims step, server skips prior validation)
role=admin            (client claims role)
```

### 5.3 Check for UI-only restrictions

```bash
# In browser: right-click on greyed-out button → Inspect Element
# Look for disabled attribute or onclick handler that checks a condition
# The underlying API endpoint may not have the same restriction
```

Alternatively, send the API request directly without clicking the UI button.

### 5.4 Identify shared flow state

If a flow uses a token or ID in the URL:
```
/checkout/confirm?orderId=12345
```
Try `orderId=12344`, `orderId=12346` — can you complete another user's checkout?

---

## 6. Common patterns and exploitation

### 6.1 Checkout flow manipulation

**Price modification (if client sends price):**
```
POST /checkout
productId=123&quantity=1&price=0.01
```
If server trusts client price → $0.01 purchase.

**Coupon stacking:**
```
POST /apply-coupon
couponCode=SAVE20
# Apply once → 20% off
# Apply again in same session → does it apply twice?
# Try different browser, different session — does "one-per-account" check fire?
```

**Add to cart at sale price, change later:**
1. Add item to cart during sale at $5
2. Return after sale ends
3. Proceed to checkout — does cart still show $5?

### 6.2 Subscription bypass — direct URL access

```
GET /dashboard/premium-feature
# As free user — check if page loads or just the menu item is hidden
```

Common pattern: the navigation checks subscription tier in JS, but the actual page endpoint only checks authentication, not authorization.

### 6.3 Multi-step skip

Payment flow: `step1=shipping` → `step2=payment` → `step3=confirm`

```
POST /checkout/confirm
# Submit confirm request directly without step2
# If server only checks that step1 was done, but not step2 → order placed without payment
```

### 6.4 Repeat one-off actions

Registration bonus:
```
# Delete account → re-register with same email (or +tag variant)
# Does welcome credit re-issue?
```

Password reset:
```
# Request reset token
# Use token (it "expires")
# Replay the same token → is it truly expired or is it reusable?
```

### 6.5 Partial commit after cancel

1. Start a sensitive action (e.g., funds transfer)
2. Cancel or disconnect mid-way
3. Check whether partial state was committed (funds debited but not credited, access granted but not logged)

### 6.6 Accessing in-progress flows of other users

```
GET /onboarding/step3?userId=1001
GET /checkout/confirm?orderId=5555
```
If the server identifies the flow by `userId` or `orderId` without verifying ownership → IDOR + logic bug combination.

---

## 7. Business impact mindset

Always assess:

- **Financial impact:** Can this be used to get goods/services for free or at reduced cost?
- **Scale:** Can this be automated and repeated? How many accounts does an attacker need?
- **Detectability:** Would the app's fraud detection catch this? (Unusual patterns? Audit logs?)
- **Reversibility:** Can the company recover (cancel orders, revoke credits)?

Impact tiers from the notes context:
- **Financial loss** — negative quantity, price modification, coupon stacking, gift card double-redemption
- **Account takeover** — flow bypass that lets attacker complete password reset, email change, or account verification without the required prerequisite
- **Privilege escalation** — skip payment for premium, direct URL access to admin features
- **Denial of service** — occupy/exhaust a finite resource (seats, invite codes) without paying
- **Information disclosure** — accessing another user's partially-completed flow reveals their data

---

## 8. Bypass techniques

| Obstacle | Approach |
|---|---|
| UI disables the button | Send the API request directly from Burp — UI blocking is client-side only |
| "Coming soon" product | Replace `productId` in add-to-cart request |
| "One coupon per account" enforced by cookie | Use a different session/account |
| Flow validates previous step token | Reuse the token from step 1 in the step 3 request |
| Checkout requires payment confirmation from payment provider | Check if the confirmation endpoint validates the payment provider's callback or trusts a client-supplied `payment_status=success` |
| Subscription check on page load | Cache/CDN may serve the premium page after initial auth |
| Server checks the step, not the previous step | Submit all steps simultaneously (race condition) |

---

## 9. False-positive checks

- **Direct URL access returns 403** → server-side authorization is present; not a bypass.
- **Price modification is rejected by back-end** → server re-fetches price from DB; note it, move on.
- **Coupon stacking blocked at second apply** → check if it was applied once or not at all; confirm the first apply still worked.
- **Step skip returns to step 1** → redirect is correct; server validates sequence.
- **Trial re-start blocked by email uniqueness** → note whether `+tag` variants work before ruling out.

Before reporting, confirm:
1. The resource/state actually changed (check balance, check DB state, check order confirmation)
2. The action is not the intended behaviour (some apps do allow coupon stacking)
3. You can reproduce it from a clean account/session

---

## 10. Chain candidates

| Chain | Paired skill | Impact |
|---|---|---|
| Checkout price manipulation + IDOR on orderId | `idor` | Purchase any user's reserved item for $0 |
| Flow step skip + race condition | `race-conditions` | Double-apply a one-time bonus before invalidation |
| Subscription bypass + XSS in premium feature | `xss` | XSS only reachable if subscription check is bypassed |
| Referral fraud + account enumeration | `idor` | Scale fraud programmatically |
| Coupon stacking + negative quantity | `param-logic` | Extreme financial manipulation |
| Access unreleased feature before embargo date | Business/reputational impact | Competitive intelligence, early access |
| Access another user's checkout → IDOR | `idor` | Steal shipping address, payment method info |

---

## 11. Reporting template

```
POTENTIAL FINDING: Business Logic Bug — <Flow Bypass | Pricing Abuse | Feature Access | Coupon Stacking | State Machine Attack>
Target: <URL / endpoint>
Flow affected: <e.g. "Checkout flow — payment step">
Normal flow:
    Step 1: <description>
    Step 2: <description>
    Step 3: <description>
Bypass:
    <e.g. "Skipped step 2 (payment) by submitting step 3 directly">
    <e.g. "Sent negative quantity=-5 on item priced $10 → credit of $50 applied to cart">
Reproduction steps:
    1. <exact step>
    2. <exact step>
    3. <exact step>
Evidence:
    <order confirmation, balance change, access to premium feature, another user's data>
Root cause:
    <e.g. "Server trusts client-supplied price without re-fetching from DB">
    <e.g. "Step 3 only checks session authentication, not whether step 2 (payment) was completed">
    <e.g. "Coupon validation checks per-session, not per-account — new session = new use">
Impact:
    <financial loss | unauthorized access | account takeover | privilege escalation | info disclosure>
Business context:
    <what an attacker could realistically do with this at scale>
Chain potential: <other skills>
Next step: <e.g. "Confirm maximum financial exposure — can this be automated across many accounts?">
```

---

## 12. Recon tracker vector strings

Only log if user explicitly says to.

- `bizlogic:checkout-price:<endpoint>` — client-supplied price trusted by server
- `bizlogic:coupon-stack:<endpoint>` — coupon stacking confirmed
- `bizlogic:flow-skip:<step>` — step skip confirmed
- `bizlogic:step-repeat:<step>` — one-off action repeatable
- `bizlogic:feature-gate:<feature>` — subscription/role gating absent server-side
- `bizlogic:unreleased:<productId>` — access to unreleased resource via API
- `bizlogic:cross-user-flow:<endpoint>` — accessed another user's in-progress flow
- `bizlogic:referral-abuse:<endpoint>` — referral self-abuse confirmed
- `bizlogic:no:<endpoint>` — tested, server-side logic is sound

---

## 13. What NOT to do

- Do NOT make real financial transactions on production to test pricing bugs without explicit program authorization — financial impact on the company from invalid orders.
- Do NOT exhaust limited resources (coupon codes, invite slots, limited stock items) while testing — other real users are affected.
- Do NOT chain into payment provider APIs or third-party fraud detection systems — those are out of scope unless explicitly in scope.
- Do NOT self-refer using the same personal details if your identity is known to the program — creates a real account action that the company may need to reverse.
- Do NOT report "greyed-out button can be clicked" as a finding without demonstrating that the API endpoint behind it also lacks authorization.
- Do NOT assume business logic bugs are low severity — a direct URL to a premium feature is a real bypass; financial manipulation findings are typically high severity.
- Do NOT auto-log to recon tracker without explicit user instruction.
