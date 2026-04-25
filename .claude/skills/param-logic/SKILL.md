---
name: param-logic
description: Parameter Logic Bugs — input boundary testing (negative/zero/null/array/float), null safety issues (omitted parameters defaulting to unexpected values), client-vs-server validation disparity, type coercion surprises, and floating-point precision bugs. Use when testing any feature that processes numeric input, omittable parameters, or has front-end validation that differs from back-end behaviour.
---

# Parameter Logic Bugs (INDEX — Parameter Logic Bugs / Whitebox Attacks)

This skill covers systematic boundary testing of parameters, null/missing parameter behaviour, front-end vs back-end validation disparity, and type coercion. It is mindset and methodology-heavy. Read top to bottom on first invocation.

---

## 1. Triggers — when this skill applies

- Any numeric parameter (quantity, price, tip amount, transfer amount, discount percentage, page/offset, age limit)
- Any parameter that has visible front-end validation (min/max, dropdown, date picker, step constraints)
- Any parameter that can be omitted from a request
- JSON bodies where field types could be changed (string → number → null → array → object)
- Weakly typed back-end (PHP, JavaScript/Node.js) that doesn't strictly type-check inputs
- Multi-parameter interactions where one parameter gates behaviour of another
- Features with "unique" or "one per user" constraints that use parameters as identifiers
- Password reset, coupon, subscription, or any flow with special numeric or string IDs

---

---

## 3. 30-second triage

For every numeric or constrained parameter, ask:
1. What happens if I send a negative value?
2. What happens if I send zero?
3. What happens if I omit this parameter entirely?
4. What happens if I send an array or object instead of a scalar?
5. What happens if I bypass the front-end constraint and send a value the UI would reject?

If any of these produces a different success-path behaviour than expected (no error, unexpected state change, access to something it shouldn't allow), this skill applies.

---

## 4. Input boundary testing checklist

Work through all of these for every in-scope parameter. Document results in the session notes.

### 4.1 Numeric boundaries

| Probe value | Why |
|---|---|
| `-1` | Negative — may flip direction of operation (debit becomes credit) |
| `-99999` | Large negative — may overflow or produce extreme result |
| `0` | Zero — may bypass "must be positive" checks |
| `0.01` | Minimal positive float — may round to zero in some currencies |
| `0.1 + 0.2` = `0.30000000000000004` | Floating point imprecision |
| `99999999999` | Very large integer — integer overflow risk |
| `1.7976931348623157e+308` | Float max — overflow |
| `2147483647` | INT_MAX for 32-bit signed int |
| `2147483648` | INT_MAX + 1 — wraps to negative in some implementations |
| `1e2` | Scientific notation — PHP loose comparison: `100 == "1e2"` is `true` |

### 4.2 Type confusion

| Probe value | Why |
|---|---|
| `"123"` vs `123` | String vs integer — does back-end enforce type? |
| `true` / `false` | Boolean — PHP: `true` == any non-zero, non-empty |
| `null` | Null — might default to 0, might skip validation |
| `[]` (empty array) | Array bypass — `strcmp(array, string)` returns null in PHP < 8 |
| `["a", "b"]` | Multi-value array — unexpected iteration |
| `{"key":"value"}` | Object — may confuse ORM or serializer |

### 4.3 String edge cases

| Probe value | Why |
|---|---|
| `""` (empty string) | May bypass non-null check |
| `" "` (whitespace only) | May pass `isset()` but fail semantic checks |
| Very long string (10,000 chars) | Buffer/DB column truncation |
| String with null byte `%00` | Premature string termination in C-based extensions |
| `0` (string zero) | PHP: `"0" == false` is `true`; `"0" == null` is `false` |
| `"true"` / `"false"` | String booleans — depends on JSON vs form parsing |
| Intentional format mismatch | Email field: submit `admin` with no `@`; date field: submit `99/99/9999` |

### 4.4 Omitted parameters

- Remove each optional-looking parameter entirely from the request
- Remove nominally required parameters and observe the default behaviour
- Ask: does omitting a parameter default it to `null`, `0`, `""`, or an admin-level default?
- Null safety bugs: if a parameter is omitted and the back-end accesses it without a null check → crash or unexpected access

### 4.5 Client-side vs server-side disparity

For every front-end constraint:
1. Identify where the constraint is enforced (JS in the browser, or back-end validation)
2. Intercept the request in Burp after the front-end validates
3. Modify the value to one the front-end would reject
4. Submit — does the back-end also reject it?

Common disparity patterns:
- UI shows a dropdown with fixed options → back-end doesn't re-validate the value
- UI enforces min/max on quantity → back-end accepts any integer
- UI marks a product as "coming soon" (no add-to-cart) → back-end accepts any valid `productId`
- UI enforces a date range → back-end trusts the submitted dates

### 4.6 Parameter interaction

Test combinations — does param A change what param B does?

- `step=2` in a multi-step form — can you jump to step 5 directly?
- `role=admin` added alongside `username=testuser`
- `discount=100` combined with `quantity=-1`
- Adding an undocumented parameter that the source code references (check JS files for hidden params)

---

## 5. Detection methodology (whitebox)

### 5.1 Find functions with user input

```bash
grep -rn "req.body\|req.params\|req.query\|\$_POST\|\$_GET\|\$_REQUEST" src/ routes/ | grep -v "sanitize\|validate\|filter"
```

### 5.2 Find loose/dynamic variables

JavaScript (Node.js):
```bash
grep -rn "var \|let " src/ routes/ | grep -v "const " | head -50
```

PHP:
```bash
grep -rn "==" src/ | grep -v "==="
```

### 5.3 Find switch/if-else without default

```bash
grep -rn "switch\|else if" src/ | grep -v "else$\|default:"
```

### 5.4 Identify null variables

JavaScript: look for uninitialized `var`/`let`, `?.` operator usage, `!` non-null assertion overrides.
PHP: look for `isset()` checks without a fallback, `$var = $_POST['key']` without `?? default`.

---

## 6. Exploitation patterns

### 6.1 Negative quantity / negative price

```
POST /cart/add
quantity=-1&productId=1234
```
If the server subtracts from the cart total → negative balance → money credited or $0 order.

```
POST /checkout/tip
tip=-50&orderId=9999
```
Reduces total below zero → effectively stealing from the restaurant.

### 6.2 Zero or zero-like bypass

```
POST /purchase
quantity=0&productId=PRO_FEATURE
```
Some apps issue the item with quantity 0 and don't enforce that quantity must be > 0.

```
POST /transfer
amount=0.001&to=attacker
```
If the app rounds down to 0 for display but processes the transfer, small amounts may accumulate.

### 6.3 Omit required parameter → null default

```
POST /api/updateProfile
{"username": "newname"}   // 'role' param omitted entirely
```
If `role` defaults to `null` and the back-end treats `null` as `admin` in a privilege check → escalation.

```
POST /api/order
{"productId": 123}   // 'price' omitted
```
If price defaults to 0 → free product.

### 6.4 Front-end disparity — access unreleased feature

The iPhone 4 pattern from notes:
1. Observe that the UI shows "coming soon" for `productId=9999`
2. Add a different product normally, capture the `addToCart` request
3. Replace `productId` with `9999`
4. If back-end doesn't re-check availability → item added
5. Proceed to checkout

### 6.5 Floating-point precision attack

```
POST /wallet/topup
amount=0.1
# If processed as float: 0.1 + 0.2 = 0.30000000000000004
# Repeated topups with small amounts may accumulate rounding surplus
```

For subscription billing: submitting `amount=9.9999999` to a $10 minimum threshold that uses `amount < 10.0` as the check. In floating point, `9.9999999 < 10.0` is true.

### 6.6 Parameter pollution (send same param twice)

```
GET /account?role=user&role=admin
POST /update (body: role=user) + (header: X-role: admin)
```
Some frameworks use first value, others use last. Check which the back-end picks.

---

## 7. Null safety specific patterns

### 7.1 Missing parameter → access with null identity

```
GET /api/data          # no userId param
# If userId defaults to null and query is SELECT * FROM data WHERE userId = null
# MySQL: WHERE userId = null matches nothing, but
# Some ORMs: null means "no filter" → returns ALL rows
```

### 7.2 Null user context access

```
GET /profile           # while partially logged in or with expired session
# If session.userId is null and the code checks: if (userId) { ... }
# null is falsy → skips auth block → reaches protected code
```

### 7.3 Optional chaining abuse

In Node.js: `user?.role` returns `undefined` if `user` is null/undefined. If checked with `==`, `undefined == null` is `true`. If the role check is `user?.role == 'user'` and role is `undefined` → `undefined == 'user'` is `false` — safe. But `user?.isAdmin` with a prototype-polluted `isAdmin` returns `true`. This bridges to the `prototype-pollution` skill.

---

## 8. Bypass techniques

| Scenario | Approach |
|---|---|
| Front-end enforces min/max via HTML `min`/`max` attributes | Burp intercept → modify value after browser validates |
| Front-end enforces with JavaScript `onchange` | Intercept the POST request after JS sends it |
| Server validates `is_numeric()` in PHP | Send scientific notation: `1e2` passes `is_numeric()` and equals 100 |
| Server rejects empty string | Try `" "` (whitespace), `null` JSON type, or omit the key entirely |
| Param removed → 400 Bad Request | Try setting it to `null`, `0`, or `false` instead of removing |
| Array rejected with error | Try nested object `{"key": {"value": 1}}` instead |

---

## 9. False-positive checks

- **Negative quantity accepted but no business impact:** verify whether the negative value actually affects balance, inventory, or pricing — not just stored without consequence.
- **Null parameter accepted but no functional difference:** confirm what the null default resolves to in the actual data flow.
- **Front-end validation bypass goes to same error as expected:** server-side validation is present and equal — mark as "disparity absent" for this param.
- **Float precision issue is sub-cent and non-exploitable at scale:** assess whether repeated exploitation is feasible or if rounding is corrected in final billing.

---

## 10. Chain candidates

| Chain | Paired skill | Impact |
|---|---|---|
| Negative quantity → $0 checkout | `business-logic` | Financial fraud |
| Null userId → all rows returned | `idor` | Mass data exposure |
| Front-end disparity → access unreleased resource | `business-logic` | Competitive advantage / unauthorized access |
| Array param bypass + type juggling | `type-juggling` | Auth bypass |
| Omitted `role` param defaults to admin | `auth-bypass` | Privilege escalation |
| Null param → crash → reveals stack trace | `ssrf`, `sqli` (hints at internals) | Info disclosure → further attack |
| Float precision in payment | `business-logic` | Financial manipulation |

---

## 11. Reporting template

```
POTENTIAL FINDING: Parameter Logic Bug — <Unexpected Input | Null Safety | Validation Disparity | Type Coercion>
Target: <URL / endpoint>
Parameter: <param name + type: query/body/header/cookie>
Normal value: <what the app expects>
Manipulated value: <what you sent>
Expected back-end behaviour: <what it should do>
Actual back-end behaviour: <what it did>
Evidence:
    <response excerpt, balance change, access to restricted resource>
Root cause:
    <e.g. "Missing back-end validation — front-end enforces min=1 but server accepts negative">
    <e.g. "Null parameter defaults to 0, which equals admin userId in the DB">
    <e.g. "Back-end trusts productId from front-end without re-checking availability">
Impact:
    <e.g. "Attacker can purchase any item for $0 by setting quantity to a negative number">
Chain potential: <other skills>
Next step: <e.g. "Confirm maximum financial damage possible with a single request">
```

---

## 12. Recon tracker vector strings

Only log if user explicitly says to.

- `param-logic:negative-value:<param>` — negative value exploit confirmed
- `param-logic:null-param:<param>` — null/omitted parameter bug confirmed
- `param-logic:disparity:<endpoint>` — front-end vs back-end validation disparity found
- `param-logic:type-coerce:<param>` — type coercion bug confirmed
- `param-logic:float-precision:<endpoint>` — floating point precision issue
- `param-logic:no:<endpoint>` — tested, server-side validation is robust

---

## 13. What NOT to do

- Do NOT make real financial transactions to test negative quantities without program permission — check `program-guidelines.txt` for allowed testing scope on payment features.
- Do NOT leave negative-quantity items in a cart on shared test accounts — other researchers or the program's monitoring may be affected.
- Do NOT send thousands of boundary values without checking rate limits — systematic fuzzing looks like automated scanning. Test a focused set of ~10 boundary values.
- Do NOT conflate "back-end accepts the value without error" with "back-end processes it incorrectly" — verify the actual state change in the response or follow-up request.
- Do NOT auto-log to recon tracker without explicit user instruction.
