# RFC 4918 coverage in litmus

Cross-reference of the 223 server-testable requirements in
[RFC4918.md](RFC4918.md) against the _litmus_ test suites: which normative
requirements _litmus_ does not test, and where the tests it does have are
weaker than they look.

The original analysis also asked where a test checked a requirement without
naming it in its failure message. That has been dealt with — see the citation
figures below — so only the coverage gaps and anomalies remain here.

## Scope

**Originally analysed against commit `58c1c68` ("CI: Always use colour, noisy
output."), where all five analysed source files were unmodified.** Findings
that have since been addressed have been removed, so what remains is the
outstanding work; see `git log` for what was fixed. Line numbers and message
strings still refer to the tree as it stood at `58c1c68` and have not been
re-derived — locate a finding by its message text, not its line number.

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
| `tested` — litmus detects a violation | 42 |
| `partial` — the requirement is touched but a material part is unchecked | 41 |
| **`NOT TESTED` — no suite exercises it** | **140** |

Of the 140 untested requirements, **87 are MUST-level** (62 MUST, 25 MUST NOT)
and 53 are SHOULD-level (37 SHOULD, 16 SHOULD NOT).

Finding (b) has been addressed: every site it listed now names its RFC
section, and all references use the single `(RFCnnnn:Sx.y)` form. The in-scope
suites currently stand at **74 of 179 assertion sites cited**:

| file | assertion sites | cited |
|---|---:|---:|
| `src/basic.c` | 35 | 15 |
| `src/common.c` | 18 | 2 |
| `src/copymove.c` | 48 | 17 |
| `src/props.c` | 30 | 15 |
| `src/locks.c` | 48 | 25 |
| **total** | **179** | **74** |

The remaining uncited sites are setup and scaffolding assertions with no
normative requirement behind them.

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

# Untested requirements

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
| 9.8.5-1 | Server must not auto-create missing intermediate collections at the COPY destination | `copymove.c` `copy_nodestcoll` | Asserts the COPY failed; never PROPFINDs `nonesuch` |
| 9.9.4-1 | Same, at the MOVE destination | `copymove.c` | No MOVE analogue of `copy_nodestcoll` exists at all |
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
destroys locks rooted on the resource), `9.6.1-1` (`delete_coll` deletes an
*empty* collection, so depth-infinity DELETE is never exercised), `9.6.1-2`,
`9.6.1-3`, `9.6.1-4`, `9.6.1-5`, `9.6.1-6`.

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
`locks.c` checks only the status code, so the whole precondition /
postcondition apparatus — `11-1`, `16-3`, `9.8.5-2`, `9.9.4-2`, `9.1.1-1`,
`9.2.1-1`, `20.6-1` — is untested. `16-4` is the sole exception and only
half-covered: `notowner_lock` checks the status code of an UNLOCK carrying a
token which identifies no lock, but nothing checks that the body carries the
`lock-token-matches-request-uri` element the precondition is about. `14.12-1` (`lockroot`) is one
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

---

# Anomalies

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
