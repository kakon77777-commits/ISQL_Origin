# ISX1 Experimental Native Profile in ISQL Origin

**Status:** Internal / Experimental W4 candidate  
**Date:** 2026-09-14  
**Depends on:** ISQL Core W2/W3 `ISX1` experimental artifact family  
**Public status:** not Public ISQL Origin profile data.

---

## 1. Purpose

W4 allows ISQL Origin to detect, wrap, validate, inspect, and unwrap the experimental `ISX1` native artifact **without decoding or assimilating its native semantic format**.

The governing rule remains:

$$
\boxed{
\text{Origin}
=
\text{Canonical Envelope}
+
\text{Profile Binding}
+
\text{Byte Preservation}
}
$$

Origin is not the `ISX1` semantic runtime.

---

## 2. Why the stable profile registry is not extended in place

Historical P1/P6 native wrappers pin the stable slot-0 profile registry by:

- registry slot;
- registry kind;
- revision;
- SHA-256 digest.

If W4 appended `ISX1` labels directly to that same registry while retaining the same conceptual lineage, the registry bytes and digest would change. Historical wrappers that pin the previous digest would then fail validation against the newly generated registry.

Therefore W4 follows:

$$
\boxed{
\text{Stable Registry Slot 0}
\neq
\text{Experimental Extension Registry Slot 1}
}
$$

The stable slot-0 registry labels remain unchanged.

---

## 3. Experimental slot-1 registry

W4 defines a separate experimental registry at bundle slot `1`.

It contains only the W4 extension labels:

```text
1  object:mem.isx1.experimental
2  codec:mem.isx1.experimental
3  isql-origin-experimental-profile-v1
```

The `ISX1` artifact descriptor uses:

```text
object kind: Ref(1, 1)
codec:       Ref(1, 2)
magic:       ISX1
version:     1
extension:   .isx1
profile:     existing isql-mem profile Ref(0, 10)
```

The extension registry reuses stable slot-0 entry-kind and payload-kind refs for ORB label entries. It does not rebind any slot-0 local ID.

---

## 4. Wrapper pin behavior

Stable artifacts such as `ISN7` require only:

$$
\boxed{
\text{pins}=(0)
}
$$

The experimental `ISX1` artifact requires:

$$
\boxed{
\text{pins}=(0,1)
}
$$

Slot 0 supplies the stable shared profile / identity / invariant vocabulary.

Slot 1 supplies the experimental `ISX1` object-kind and codec refs.

The wrapper validator requires the actual registry-pin set to equal the artifact's required registry-slot set exactly.

Therefore:

- an `ISX1` wrapper missing slot 1 fails closed;
- a stable `ISN7` wrapper carrying an unnecessary slot-1 pin fails closed.

---

## 5. Byte-exact preservation

For native bytes $b$:

$$
\boxed{
\operatorname{Unwrap}(\operatorname{Wrap}(b))=b
}
$$

continues to be the W4 invariant.

Origin computes and binds the native SHA-256 digest and stores the original native bytes in the payload table.

It does not:

- decode the `ISX1` block-width grammar;
- validate 65/255/256/4096-bit coordinates itself;
- reinterpret `ISX1` sequence values;
- migrate `ISX1` to `ISN7`;
- change the native bytes.

Native semantic validation remains the responsibility of the ISQL Core experimental runtime / conformance implementation.

---

## 6. Compatibility boundary

W4 is intentionally stacked on Origin P6 because P6 is the current latest Origin line.

W4 does not revise the P6 independent implementation claims for the existing OMIR/ORB profile set.

The stable slot-0 registry generator remains logically unchanged. Existing native artifact descriptors keep the same refs, magic values, native versions, and codecs.

The new experimental descriptor is additive and references only slot-1 local IDs for its new object kind and codec.

---

## 7. Tests

`tests/test_isx1_experimental_profile.py` covers:

1. `ISX1` detection as `mem.isx1.experimental`;
2. byte-exact wrap / validate / unwrap;
3. required registry pins `(0, 1)`;
4. absence of `isx1` labels from the stable slot-0 registry;
5. existing `ISN7` wrapper behavior remaining slot-0-only;
6. fail-closed validation if an `ISX1` wrapper loses its experimental pin;
7. fail-closed validation if a stable wrapper is injected with an unnecessary experimental pin.

The fixture used for `ISX1` is a fixed W3 positive 65-bit frame, not an Origin-generated native artifact.

---

## 8. Non-goals

W4 does not:

- make `ISX1` Public;
- implement an `ISX1` decoder in Origin;
- alter stable slot-0 registry semantics;
- change OMIR wire format;
- change ORB wire format;
- define DSR wide-value semantics;
- establish cloud or SEDB integration;
- promote any experimental ref into the stable Public profile registry.

---

## 9. Promotion rule

If a future extended-width ISQL memory format becomes Public, it must receive a deliberate Public profile allocation and migration/conformance review.

The W4 slot-1 experimental refs must not be treated as automatically frozen Public assignments merely because they exist in this branch.

Therefore:

$$
\boxed{
\text{Experimental Profile Registration}
\neq
\text{Public Profile Allocation}
}
$$
