# RFC 4918 coverage in litmus

Cross-reference of the 223 server-testable requirements in
[RFC4918.md](RFC4918.md) against the _litmus_ test suites, answering two
questions:

* **(a)** which normative requirements _litmus_ does not test at all;
* **(b)** where _litmus_ does test a requirement but the failure or warning
  message doesn't say which requirement was violated.

## Scope

**This is a point-in-time analysis, run against commit `58c1c68` ("CI: Always
use colour, noisy output.").** All five analysed source files were unmodified
at that commit. Line numbers, message strings and counts below describe the
tree as it stood there; they are not maintained against later changes, so
re-run the analysis rather than patching this document.

Four suites were analysed: `src/basic.c` (together with `src/common.c`, which
holds `options()` and the shared helpers), `src/copymove.c`, `src/props.c` and
`src/locks.c`.

`src/lockbomb.c`, `src/protected.c`, `src/http.c` and `src/largefile.c` were
**excluded** — they are stress and security tests rather than DAV compliance
tests. Their absence from this document is not a claim that they lack coverage;
they were not examined. (`largefile.c` was examined before being excluded and
was found to touch no RFC 4918 requirement at all — every assertion in it is
RFC 9110 transport behaviour or a litmus-internal round-trip check.)

Requirement coverage is scored from what _litmus_ can actually detect. A
`PRECOND()` → `SKIP` or a `t_context()` + `SKIPREST` is neither pass nor fail
and is **not** counted as coverage.

## Summary

| | count |
|---|---:|
| Server-testable requirements in RFC4918.md | 223 |
| `tested` — litmus detects a violation | 39 |
| `partial` — the requirement is touched but a material part is unchecked | 41 |
| **`NOT TESTED` — no suite exercises it** | **143** |

Of the 143 untested requirements, **89 are MUST-level** (63 MUST, 26 MUST NOT)
and 54 are SHOULD-level (38 SHOULD, 16 SHOULD NOT).

For finding (b), the in-scope suites contain **169 message-emitting assertion
sites**, of which **19 carry an RFC citation** — 89% uncited. A 20th reference,
`[RFC9110:S15.3.2]` at `src/basic.c:217`, is in a comment rather than a message.

| file | assertion sites | cited |
|---|---:|---:|
| `src/basic.c` | 27 | 8 |
| `src/common.c` | 18 | 0 |
| `src/copymove.c` | 47 | 9 |
| `src/props.c` | 30 | 1 |
| `src/locks.c` | 47 | 1 |
| **total** | **169** | **19** |

`src/locks.c` is the outlier: one citation across 47 sites, in the suite whose
requirements are the most intricate in the specification.

## Three ways coverage silently disappears

Before the gap list, three mechanisms that make the numbers above optimistic.
In each case _litmus_ exits 0 and reports nothing alarming:

1. **The Class 2 gate.** `src/locks.c:38-47` — `precond()` returns `SKIPREST`
   when `!i_class2`, so **all 40 subsequent entries in the locks table vanish**
   against a server that does not advertise `2` in its `DAV` header. `i_class2`
   is set from the OPTIONS response in `src/common.c:443`, so the gate keys on
   the *advertisement*, not on observed LOCK support: a server whose only lock
   defect is a missing `2` in the header is never tested for any other lock
   defect. The sole artefact is a `t_warning` at `src/common.c:441`.
2. **Missing ETag disables four conditional-PUT tests.** `get_etag()`
   (`src/common.c:448-460`) returns NULL when the HEAD is not 200 or the header
   is absent. `PRECOND(etag && gotlock)` at `src/locks.c:366`, `:386` and
   `PRECOND(gotlock && etag != NULL)` at `:476`, `:498` then silently SKIP
   `cond_put`, `fail_cond_put`, `complex_cond_put` and `fail_complex_cond_put`,
   taking most 10.4.4-1 coverage with them. RFC 4918 permits a server not to
   return an ETag (15.6-1 is conditional on the header's presence), so this is
   reachable against a compliant server.
3. **No Depth-1 PROPFIND exists anywhere in litmus.** `NE_DEPTH_ONE` has zero
   occurrences in `src/`. Every PROPFIND in the tree is Depth 0, which makes
   9.1-2 half-covered and 9.1-9, 9.1-10, 14.24-1, 8.3-1 and 8.3-3 unreachable
   as the suites are currently written.

---

# (a) Untested requirements

Grouped by the suite each would naturally belong to. Requirements marked
**[hard]** need a server that can be made to fail on demand, a long run, or a
second credential set, and are listed for completeness rather than as
actionable work. Requirements marked **[neon]** cannot be expressed through the
neon convenience API in use and need a hand-built `ne_request`.

## Cheapest high-value additions

These are MUST-level, squarely inside an existing suite's remit, and each is a
small addition to a test that already sets up the necessary state:

| Req | Requirement | Where it belongs | Why it's cheap |
|---|---|---|---|
| 9.6-3 | After a successful DELETE, GET/HEAD/PROPFIND on the URL must return 404 | `basic.c` `delete`, `delete_coll` | Both tests assert only that the DELETE succeeded; nothing re-requests the URL |
| 9.3.1-1 | Server must not auto-create missing intermediate collections | `basic.c` `mkcol_no_parent`, `put_no_parent` | Both check the 409 but never probe whether the parent was created anyway |
| 9.8.5-1 | Same, for the COPY destination | `copymove.c` `copy_nodestcoll` | Asserts the COPY failed; never PROPFINDs `nonesuch` |
| 9.9.4-1 | Same, for the MOVE destination | `copymove.c` | No MOVE analogue of `copy_nodestcoll` exists at all |
| 7.3-2 | A lock-null resource should not disappear when its lock goes away | `locks.c` | `T(unmapped_lock), T(unlock)` already builds the exact state; one HEAD after the unlock answers it |
| 7.3-3 | MKCOL against a lock-null resource must fail | `locks.c` | `prep_collection`/`ne_mkcol` machinery is already present |
| 7.6-2, 7.6-3 | MOVE must not carry the lock; destination lock must absorb the moved resource | `locks.c` | The exact mirror of what `copy()` already does correctly for 7.6-1 |
| 6.5-1 | Lock tokens must be unique | `locks.c` | Five tokens are minted across the suite and no two are ever compared |
| 15.4-1, 15.2-1, 9.1-8 | `getcontentlength`/`displayname` defined; 404 propstat for an absent property | `props.c` `d0_results` | `props.c:36-44` already *requests* `getcontentlength`, `displayname`, `{NS}foo` and `{NS}bar`; `d0_results` inspects only the `DAV:collection` flag and discards the rest |

## §4–§5 Data model and collections

`5.2-1`, `5.2-2`, `5.2-5` (namespace consistency, preferred segment) — need a
Depth-1 PROPFIND. `4.3-3` (`xml:space` ignored, whitespace significant) — every
property value in `props.c` is whitespace-free. `4.3-2` (prefix preservation),
`5.2-3`, `5.2-4` (trailing-slash handling) untested.

Note that **8.3-3 and 5.2-4 are actively defeated rather than merely missing**:
`d0_results` compares hrefs with `ne_path_compare()` (`src/props.c:71`), which
by design treats `.../litmus` and `.../litmus/` as equal, so a collection href
returned without its trailing slash cannot trip the warning at `src/props.c:72`.

## §6–§7 Locking model — `locks.c`

Untested MUSTs: `6.1-3`, `6.1-4` (lock removal when membership changes or the
lock-root becomes unmapped — `unlock` is always the terminal operation, nothing
deletes or moves a locked resource *with* its token and re-checks
lockdiscovery), `6.7-1` and `7.3-4` (`DAV:supportedlock` — the string
`supportedlock` appears **nowhere in `src/`**), `7.4-1` (depth-infinity LOCK
over a collection with a conflicting member — `prep_collection` creates the
collection empty and locks it *before* populating it, precisely the ordering
that avoids this case), `7.6-2`, `7.6-3`.

**[hard]** `6.4-1`, `6.4-2` (principal identity): `i_session` and `i_session2`
share one credential set — `auth()` at `src/common.c:261-267` copies the single
global `i_username`/`i_password` into both. The `notowner_*` test names are
therefore misleading: they test *lock token not submitted*, not *a different
principal*. Testing 6.4-1 needs a second credential set, which litmus's CLI
does not accept.

**[hard]** `6.6-2`, `6.6-3` (timeout expiry) — the suite requests
`Second-3600` and never waits.

## §9.1/§9.2 PROPFIND and PROPPATCH — `props.c`

Untested MUSTs: `9.1-5` (empty request body means `allprop` — never sent),
`9.1-9` (a `response` per member URL — needs Depth 1), `9.2-3` (reject a body
without `propertyupdate`), `9.2-5` (atomicity/rollback), `9.2-6` (the response
must be 207), `9.2-7` (must not be cached).

`9.2-6` deserves emphasis: `ne_proppatch` ends in `ne_simple_request`, which
checks only the 2xx class, and `do_patch` (`src/props.c:393`) checks
`klass != 2`. **A server answering PROPPATCH with a bare `200 OK` and no body
passes every PROPPATCH test in the suite.** Contrast PROPFIND, where 9.1-6 is
genuinely enforced — but by neon rather than by litmus: `ne_accept_207`
(`neon/src/ne_207.c:300`) accepts only 207, so a non-207 yields no callback and
the pre-set `"No responses returned"` context fires.

## §9.3/§9.6/§9.7 MKCOL, DELETE, PUT — `basic.c`

Untested: `9.3-4` (bodyless MKCOL yields no members), `9.3-6`, `9.6-1` (DELETE
destroys locks rooted on the resource), `9.6-3`, `9.6.1-1` (`delete_coll`
deletes an *empty* collection, so depth-infinity DELETE is never exercised),
`9.6.1-2`, `9.6.1-3`, `9.6.1-4`, `9.6.1-5`, `9.6.1-6`, `9.3.1-1`.

## §9.8/§9.9 COPY and MOVE — `copymove.c`

**[neon]** `9.8-1`, `9.9-1` (`Destination` must be present), `9.8.3-1` (COPY
with no Depth header defaults to infinity), `10.6-1` (absent `Overwrite` means
`T`) — neon unconditionally emits `Destination`, `Overwrite` and, for COPY,
`Depth`, so each needs a hand-built `ne_request_create(i_session, "COPY", src)`.
None needs a cooperating server; all four are cheap.

**[hard]** `9.8.3-5` … `9.8.3-9` and `9.9.2-4` … `9.9.2-8` — partial-failure
behaviour during a deep COPY/MOVE: skipping the failed subtree, the 207
Multi-Status contents, and 424/201/204 suppression. All need a server that can
be made to fail on one member of a deep tree.

Also untested: `9.8.2-1` … `9.8.2-3` (property duplication on COPY — the MOVE
side, `9.9.1-3`, *is* covered by `propmove` in `props.c`, but nothing covers the
COPY equivalents), `9.9.1-1`, `9.9.1-2`, `9.8.3-3`, `9.9.2-2`, `10.3-1`,
`10.3-2`, `10.6-3`, `9.8-3`, `9.9-3`.

## §9.10/§9.11 LOCK and UNLOCK — `locks.c`

**[neon]** `9.10.1-1` (bodyless LOCK on an unlocked URL must not create a lock),
`9.10.3-1` (`Depth: 1` must be rejected), `9.10.3-6` (no Depth header means
infinity), `9.10.2-2` (Depth ignored on refresh) — `ne_lock()` always sends a
body and a Depth header, `ne_lock_refresh()` never sends Depth.

**[hard]** `9.10.3-4`, `9.10.3-5`, `9.11-3`. Compounding the difficulty for
9.10.3-4: `ne_lock()` converts a 207 response into `NE_ERROR`
(`neon/src/ne_locks.c:794-797`), so a *compliant* Multi-Status would currently
be reported as a LOCK failure. Any test here must bypass `ne_lock()`.

Also untested: `9.10-2`, `9.11-5` (must not be cached), `9.10.6-1`, `9.10.4-2`,
`9.10.4-3` (GET on a lock-null resource must succeed).

## §13–§17 Multi-Status, XML elements, extensibility

Untested MUSTs: `13.2-1` (`location` element in redirect Multi-Status),
`14.5-1`, `14.7-1`, `14.8-1`, `14.18-1`, `14.24-1` (duplicate `href` in one
`multistatus` — needs Depth 1), `14.26-1` (`xml:lang` persisted and retrievable
— a notable gap, since `props.c` exercises namespaces heavily but never
language tagging), `14.17-1`, `16-1`, `16-2`, `16-5`, `17-4` (no DTD
validation), `15.9-2`.

**_litmus_ never parses a WebDAV error body.** Every 423-producing site in
`locks.c` checks only `atoi()` of the status line, so the whole precondition /
postcondition apparatus — `11-1`, `16-3`, `16-4`, `9.8.5-2`, `9.9.4-2`,
`9.1.1-1`, `9.2.1-1`, `20.6-1` — is untested. `14.12-1` (`lockroot`) is one
`ONCMP` away: `compare_locks` (`src/locks.c:270-275`) compares only token and
owner, skipping `lock->uri`, which is where neon stores the parsed `lockroot`.

## §15 DAV properties — `props.c`

**No protected-property requirement is tested anywhere in the tree.** No
PROPPATCH is ever attempted against `DAV:getetag` (15.6-2),
`DAV:lockdiscovery` (15.8-1), `DAV:supportedlock` (15.10-1),
`DAV:getlastmodified` (15.7-3) or `DAV:resourcetype` (15.9-3) — each of which is
directly testable by trying to set it and expecting a 403. `src/protected.c`
tests a server-private *collection*, not DAV protected *properties*, so it does
not fill this gap.

Likewise untested: `15.1-1` … `15.1-3` (`creationdate`), `15.2-1`, `15.2-2`
(`displayname`), `15.3-1` … `15.3-3` (`getcontentlanguage`), `15.4-1`
(`getcontentlength`), `15.5-1`, `15.5-2` (`getcontenttype`), `15.6-1`
(`getetag`), `15.7-4`, `15-1` (LWS stripping).

## §18–§20 Compliance classes and security

`18.2-1` — only the `DAV` header *value* is inspected; nothing cross-checks that
a server claiming "2" actually supports LOCK, `DAV:supportedlock`,
`DAV:lockdiscovery`, the Timeout response header and the `Lock-Token` request
header. Of those five, `locks.c` exercises three; the Timeout response header is
never read back and `DAV:supportedlock` is never requested. `18.3-1` (class 3
implies class 1) untested. `10.1-2` (OPTIONS on a non-WebDAV path should not
advertise WebDAV) untested — `options()` only ever runs OPTIONS on `i_path`.

`20.1-1` … `20.1-3` (Basic over an insecure connection, Digest support) are
untested and would fit naturally in a suite that already knows whether the
session is TLS.

---

# (b) Tested but uncited

150 of the 169 assertion sites carry no RFC reference. Listed below are the
sites where a citation would carry real information — a reader hitting the
failure needs the spec text. Suggested citations use litmus's existing in-code
convention, `(RFC4918:Sx.y)`, which is the majority form in the tree.

## `src/common.c` — 0 of 18 cited

| line | current message | suggested |
|---|---|---|
| 439 | `"server does not claim WebDAV compliance"` | `(RFC4918:S18.1)` — 10.1-1/18.1-1 |
| 441 | `"server does not claim Class 2 compliance"` | `(RFC4918:S18.2)` — 18.2-3 |

The second is load-bearing well beyond its own message: it is the only visible
consequence of the Class 2 gate that disables the entire locks suite.

## `src/locks.c` — 1 of 47 cited

Nine of the ten `t_warning`s are uncited, and every one is §6/§7/§10.4
material:

| line | current message | suggested |
|---|---|---|
| 128 | `"DELETE failed with %d not 423"` | `(RFC4918:S7.5)` |
| 136 | `"MOVE failed with %d not 423"` | `(RFC4918:S9.9.4)` |
| 142 | `"COPY failed with %d not 423"` | `(RFC4918:S9.8.5)` |
| 148 | `"PROPPATCH failed with %d not 423"` | `(RFC4918:S7.5)` |
| 154 | `"PUT failed with %d not 423"` | `(RFC4918:S7.5)` |
| 183 | `"LOCK failed with %d not 423"` | `(RFC4918:S9.10.5)` |
| 399 | `"PUT failed with %d not 412"` | `(RFC4918:S10.4.1)` |
| 418 | `"PUT failed with %d not 412"` | `(RFC4918:S10.4.1)` |
| 464 | `"PUT failed with %d not 423"` | `(RFC4918:S10.4.1)` — but see the level mismatch below |

The FAIL-level sites are equally bare. Highest value, by how often a reader must
go to the RFC to interpret the failure:

| line | current message | suggested |
|---|---|---|
| 124 | `"DELETE of locked resource should fail"` | `(RFC4918:S7.5)` — 7.5-1 |
| 131 | `"MOVE of locked resource should fail"` | `(RFC4918:S7.5)` — 7.5-1 |
| 138 | `"COPY onto locked resource should fail"` | `(RFC4918:S7.5)` — 7.5-1 |
| 144 | `"PROPPATCH of locked resource should fail"` | `(RFC4918:S7.5)` — 7.5-1 |
| 150 | `"PUT on locked resource should fail"` | `(RFC4918:S7.5)` — 7.5-1 |
| 170 | `"UNLOCK with bogus lock token"` | `(RFC4918:S10.5)` — 10.5-1 |
| 176 | `"LOCK on locked resource"` | `(RFC4918:S9.10.5)` — 9.10.5-1 |
| 258 | `"found %d locks on copied resource"` | `(RFC4918:S7.6)` — 7.6-1 |
| 304 | `"lock discovery failed"` | `(RFC4918:S6.8)` — 6.8-1 |
| 318, 550 | `"LOCK refresh"`, `"indirect refresh LOCK on %s via %s: %s"` | `(RFC4918:S9.10.2)` — 9.10.2-1/9.10.2-3 |
| 328 | `"UNLOCK"` | `(RFC4918:S9.11)` — 9.11-2/9.11-4 |
| 272, 273 | `ONCMP(exp->token, act->token, "compare discovered lock", "token")` and the `"owner"` variant | `(RFC4918:S14.17)` — 14.17-2 |

## `src/props.c` — 1 of 30 cited

| line | current message | suggested |
|---|---|---|
| 146 | `"PROPFIND with %s got %d response not 400"` | `(RFC4918:S8.2)` — 8.2-4 |
| 366 | `"PROPFIND response %s was not well-formed: %s"` | `(RFC4918:S8.2)` — 8.2-3 |
| 369, 374 | `"no Content-Type in PROPFIND response"`, `"unexpected content-type '%s/%s'"` | `(RFC4918:S9.1)` — 9.1-6 |
| 77 | `"Base collection did not define {DAV:}collection property"` | `(RFC4918:S15.9)` — 14.3-1/15.9-1 |
| 248, 251, 255 | `"Property %d omitted from results with no status"` etc. | `(RFC4918:S9.1)` — 9.1-7/9.1-8 |
| 306 | `ONM2REQ("MOVE", ...)` in `propmove` | `(RFC4918:S9.9.1)` — 9.9.1-3, the one place litmus tests "dead properties MUST be moved" |
| 461, 483 | `"PROPPATCH remove then set"` | `(RFC4918:S9.2)` — 9.2-4, document-order processing |
| 416, 441, 508 | `"PROPPATCH of property with null namespace"` etc. | `(RFC4918:S17)` — 17-2, "the server MUST record all XML elements" |

## `src/copymove.c` — 9 of 47 cited

The cited assertions are all in `copy_simple`, `copy_overwrite`, `copy_abspath`
and `copy_nodestcoll`. Everything in `copy_coll`, `copy_shallow`, `move` and
`move_coll` is bare. The most conspicuous omissions are the MOVE status
warnings, which are the exact analogues of cited COPY warnings:

| line | current message | suggested |
|---|---|---|
| 279 | `"MOVE to new resource didn't give 201"` | `(RFC4918:S9.9.4)` — analogue of the cited `:62` |
| 298 | `"MOVE to existing collection resource didn't give 204"` | `(RFC4918:S9.9.4)` — analogue of the cited `:88` |
| 344, 347 | `"MOVE-on-existing-coll should fail"`, `"MOVE-on-existing-coll with overwrite"` | `(RFC4918:S9.9.3)` — analogue of the cited `:186`/`:189` |
| 249 | `"DELETE on \`%s' should fail with 404: got %d"` | `(RFC4918:S9.8.3)` — 9.8.3-2, the Depth-0 requirement under test |
| 179, 236 | `"collection COPY \`%s' to \`%s': %s"` | `(RFC4918:S9.8.3)` — 9.8.3-2 |

## `src/basic.c` — 8 of 27 cited

| line | current message | suggested |
|---|---|---|
| 242 | `"MKCOL on plain resource \`%s' succeeded!"` | `(RFC4918:S9.3)` — 9.3-1; the sibling check at `:310` is cited (wrongly), this one not at all |
| 251, 325 | `"DELETE on normal resource failed: %s"`, `"DELETE on collection \`%s': %s"` | `(RFC4918:S9.6)` — 9.6-2 |

---

# Anomalies

## Wrong, stale or malformed citations

All confirmed by reading the cited RFC sections:

| site | citation | problem |
|---|---|---|
| `basic.c:310` | `(RFC4918:S9.1)` | **§9.1 is PROPFIND.** The requirement — MKCOL on an existing collection must fail — is §9.3 (9.3-1). The most misleading citation in the tree: plausible-looking and pointing at an unrelated method. |
| `basic.c:315` | `(RFC4918:S9.3.2)` | §9.3.2 is "Example - MKCOL". MKCOL status codes are §9.3.1. |
| `basic.c:266` | `(RFC2518:S3)` | Obsolete RFC, *and* §3 of RFC 2518 is "Terminology". RFC 4918 §9.6 does not state the 404 either — this test has no RFC 4918 requirement behind it; the authority is RFC 9110 §15.5.5. |
| `basic.c:370` | `[RFC4918:S9.3)` | Mismatched bracket/paren. |
| `basic.c:338` | `(RFC4918:9.3)` | Missing the `S`, three lines above `[RFC4918:S9.3]` at `:343` — two spellings and two delimiters inside one 12-line function. |
| `copymove.c:77`, `:288` | `(RFC4918:10.6)` | Missing the `S`. **The section is correct**: §10.6 carries the only RFC 2119 statement of the 412 ("the method MUST fail with a 412", = 10.6-2), whereas §9.8.5's 412 entry is a descriptive status-code list item with no normative keyword. Fix the spelling, not the section. |
| `props.c:588` | `RFC4918:S15.7` | Bare — no parens or brackets, unlike every other citation in the tree. |

Five delimiter shapes are in use across the tree: `(RFC4918:Sx.y)` ×9,
`[RFC4918:Sx.y]` ×3, `(RFC4918:x.y)` ×3, bare ×1, mismatched ×1. The majority
form is `(RFC4918:Sx.y)`.

## Level mismatches

_litmus_'s dominant idiom — **FAIL on the behaviour, WARN on the exact status
code** — is followed almost everywhere and is correct: RFC 4918 rarely mandates
a specific code (7.5-1's MUST is that the method *fail*, not that it return
423). The genuine mismatches are these:

**1. `locks.c:575` — a MUST checked only by a warning, with no behaviour check
underneath it.** 7.3-5 is unambiguous: a LOCK creating a resource "MUST
indicate that a resource was created, by use of the 201 Created response code".
The only assertion is `t_warning("LOCK on unmapped url returned %d not 201
(RFC4918:S7.3)")`. Unlike the 423/412 cases there is no underlying behaviour
check — nothing GETs, PROPFINDs or HEADs the URL — so **a server that returns
200 having created nothing produces a passing run with one warning.**

**2. `props.c:585-594` — the RFC 4918 requirement is warned, the weaker HTTP
requirement is enforced.** The block reads:

```c
    tval = ne_rfc1123_parse(value);
    if (tval == -1) {
        t_warning("getlastmodified value was not RFC1123-format per RFC4918:S15.7");
    }

    if (ne_httpdate_parse(value) == -1) {
        t_context("could not parse getlastmodified value as HTTP-date");
        r->result = FAIL;
    }
```

§15.7 specifies `Value: rfc1123-date`, and §4.1 makes live-property value
syntax normative (15.7-2 with 4.1-1). But `ne_httpdate_parse`
(`neon/src/ne_dates.c:263`) falls back through RFC 1036 and asctime forms. So a
server returning `Sunday, 06-Nov-94 08:49:37 GMT` violates RFC 4918 and earns
only a warning, while the hard FAIL tests the strictly weaker RFC 9110
`HTTP-date`. The levels are inverted relative to the specifications.

**3. `locks.c` levels the same requirement three ways.** 10.4.1-1 is warned as
"not 412" at `:399` and `:418`, warned as **"not 423"** at `:464`, and hard-failed
at `:510`. `fail_cond_put` and `cond_put_corrupt_token` issue structurally
identical requests — locked resource, invalid lock token, valid ETag — yet
expect different status codes. One of the two warnings is wrong, and because
both are warnings nobody has had to decide which.

**4. `props.c:248` vs `:251`.** A property entirely absent from the multistatus
is a 9.1-7/9.1-8 *behaviour* failure (the RFC requires a `response` carrying
404), but it only warns at `:248`. The adjacent `:251` — "status for missing
property was not 404" — is the genuine status-code nit and correctly warns. The
two arms are mis-graded relative to each other.

**5. `basic.c` disagrees with itself on the PUT-create status.** `:154` warns
`"PUT of new resource gave %d, should be 201"`; `:213-215` hard-fails on the
same condition with `"MUST return 201"`. Same requirement (RFC 9110 §9.3.4), two
levels, one file. A deliberate decision either way would be an improvement.

## Vacuous or misdirecting tests

- **`copymove.c` 9.8.4-2 is effectively vacuous.** `copy_coll` copies `ccsrc` to
  both `ccdest` and `ccdest2`, then COPYs `ccdest2` over `ccdest` — two
  collections with *identical* membership, so "merging the membership of source
  and destination is not compliant" cannot fail. A real test needs the
  destination to hold a member the source does not. The same hole applies to
  9.9.3-1 in `move_coll`.
- **MOVE never verifies the source is gone.** Neither `move` (`:276`) nor
  `move_coll` (`:341`) checks that the source URL became unmapped — the source
  half of 9.9.2-3.
- **`locks.c` 9.10.1-2 / 14.17-2 is weaker than it reads.** `ne_lock()`
  overwrites `lock->owner` with the value the server returned
  (`neon/src/ne_locks.c:812-815`), so `compare_locks` compares the
  LOCK-response owner against the PROPFIND-lockdiscovery owner — a
  server-internal consistency check. A server that uniformly rewrote the owner
  would pass.
- **`props.c` `propfind_returns_wellformed` never checks the response status.**
  A 4xx leaves `ne_xml_failed(p)` at 0 because the reader never ran, so the test
  fails only incidentally via the Content-Type assertion.
- **`copymove.c:249` infers non-existence from a DELETE returning 404.** A
  server answering 403 or 405 for a DELETE of an unmapped URL fails this test
  while being perfectly compliant on the 9.8.3-2 Depth behaviour under test. Per
  the file's own idiom this should FAIL on "the child exists" and warn on the
  code.

## Stale comments and message bugs

Not RFC coverage issues, but found while reading and worth fixing alongside:

- `locks.c:173-174` — *"2518 doesn't really say what status code that UNLOCK
  should fail with"*. RFC 4918 §9.11.1 does enumerate UNLOCK status codes, and
  §16 defines `lock-token-matches-request-uri` for a Request-URI outside the
  lock's scope. The comment still holds for the *specific* case tested (a
  well-formed token identifying no lock, which remains unspecified), but the
  citation and the general claim are stale.
- `props.c:382-384` — comments that `do_patch` will *"do an XML parse on the
  response to make sure its well-formed"*. It does not: `do_patch`
  (`:385-397`) attaches no parser and discards the body. PROPPATCH response
  well-formedness is unchecked throughout the suite.
- `copymove.c:182-184` — the second `ne_copy` targets `cdest2` but the failure
  message formats `cdest`, so a failure misreports the destination.
- `copymove.c:283` — a sentence is passed as `ONM2REQ`'s *method* argument,
  rendering as `MOVE on existing resource with Overwrite: F succeeded `src2' to
  `dest': <err>`.
- `props.c:483` — `propsetremove` passes `"PROPPATCH remove then set"`, which is
  `propremoveset`'s string and the reverse of what this test does; a failure in
  either test reports identically.
- `locks.c:570-572` — reports `("LOCK on %s via %s: %s", coll, res, ...)`, where
  `coll` is a collection from the previous test group, unrelated to the unmapped
  URL being locked.
- `props.c:134-154` — `do_invalid_pfind` returns before `ne_request_destroy` on
  both failure paths, leaking `req` in tests that carry `T_CHECK_LEAKS`.
