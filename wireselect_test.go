package main

import (
	"sync/atomic"
	"testing"
	"time"
)

func expectedBinaryMasks() []byte {
	out := make([]byte, 0, 32)
	for n := 0; n < 256; n++ {
		mask := byte(n)
		if validBinaryHeaderMask(mask) {
			out = append(out, mask)
		}
	}
	return out
}

func expectedXORMasks() []byte {
	out := make([]byte, 0, 96)
	for n := 0; n < 256; n++ {
		mask := byte(n)
		if validXORHeaderMask(mask) {
			out = append(out, mask)
		}
	}
	return out
}

func TestProfileCandidatesUseOnlyMathematicallyValidDirectMasks(t *testing.T) {
	selector := &wireSelector{configured: WireAuto}
	candidates := selector.profileCandidates()
	binaryCount, bpCount, xorCount := 0, 0, 0
	seen := make(map[wireChoice]bool, len(candidates))
	for _, candidate := range candidates {
		if seen[candidate] {
			t.Fatalf("duplicate candidate: %s", candidate)
		}
		seen[candidate] = true
		if candidate.cover.Enabled {
			t.Fatalf("normal discovery must not use a cover profile: %s", candidate)
		}
		switch candidate.mode {
		case WireBinary:
			binaryCount++
			if !validBinaryHeaderMask(candidate.mask) {
				t.Fatalf("invalid B mask: %02x", candidate.mask)
			}
		case WireBP:
			bpCount++
			if !validBinaryHeaderMask(candidate.mask) {
				t.Fatalf("invalid BP mask: %02x", candidate.mask)
			}
		case WireXOR:
			xorCount++
			if !validXORHeaderMask(candidate.mask) {
				t.Fatalf("invalid X mask: %02x", candidate.mask)
			}
		default:
			t.Fatalf("unknown candidate: %s", candidate)
		}
	}
	if binaryCount != 32 || bpCount != 32 || xorCount != 96 {
		t.Fatalf("profiles B=%d BP=%d X=%d, want B=32 BP=32 X=96", binaryCount, bpCount, xorCount)
	}
	if len(candidates) != 160 {
		t.Fatalf("auto candidates=%d, want 160", len(candidates))
	}
}

func TestBinaryMasksAreExactly00ThroughF8InStepsOf08(t *testing.T) {
	want := expectedBinaryMasks()
	if len(want) != 32 {
		t.Fatalf("binary mask count=%d, want 32", len(want))
	}
	for i, mask := range want {
		if mask != byte(i*8) {
			t.Fatalf("binary mask[%d]=%02x, want %02x", i, mask, byte(i*8))
		}
	}
	for _, mode := range []string{WireBinary, WireBP} {
		candidates := (&wireSelector{configured: mode}).profileCandidates()
		if len(candidates) != len(want) {
			t.Fatalf("mode %s candidates=%d, want %d", mode, len(candidates), len(want))
		}
		for i, candidate := range candidates {
			if candidate.mode != mode || candidate.mask != want[i] || candidate.cover.Enabled {
				t.Fatalf("mode %s candidate[%d]=%s mask=%02x, want direct/%02x", mode, i, candidate, candidate.mask, want[i])
			}
		}
	}
}

func TestXORMasksAreExactlyDirectClassifierValidSet(t *testing.T) {
	want := expectedXORMasks()
	if len(want) != 96 {
		t.Fatalf("X mask count=%d, want 96", len(want))
	}
	candidates := (&wireSelector{configured: WireXOR}).profileCandidates()
	if len(candidates) != len(want) {
		t.Fatalf("X candidates=%d, want %d", len(candidates), len(want))
	}
	for i, candidate := range candidates {
		if candidate.mode != WireXOR || candidate.mask != want[i] || candidate.cover.Enabled {
			t.Fatalf("X candidate[%d]=%s mask=%02x, want direct/%02x", i, candidate, candidate.mask, want[i])
		}
		if ('U'^candidate.mask)&7 < 5 {
			t.Fatalf("X candidate[%d] is classifier-invalid: %02x", i, candidate.mask)
		}
	}
}

func TestAutoInterleavesOnlyValidMasksInNumericOrder(t *testing.T) {
	candidates := (&wireSelector{configured: WireAuto}).profileCandidates()
	want := make([]wireChoice, 0, 160)
	for n := 0; n < 256; n++ {
		mask := byte(n)
		if validBinaryHeaderMask(mask) {
			want = append(want,
				wireChoice{mode: WireBinary, mask: mask},
				wireChoice{mode: WireBP, mask: mask},
			)
		}
		if validXORHeaderMask(mask) {
			want = append(want, wireChoice{mode: WireXOR, mask: mask})
		}
	}
	if len(candidates) != len(want) {
		t.Fatalf("auto candidates=%d, want %d", len(candidates), len(want))
	}
	for i := range want {
		if candidates[i] != want[i] {
			t.Fatalf("auto candidate[%d]=%s/%02x, want %s/%02x", i, candidates[i].mode, candidates[i].mask, want[i].mode, want[i].mask)
		}
	}
}

func TestManualWireUsesOnlyValidProfilesForThatFamily(t *testing.T) {
	for _, tc := range []struct {
		mode string
		want int
	}{{WireBinary, 32}, {WireBP, 32}, {WireXOR, 96}} {
		selector := &wireSelector{configured: tc.mode}
		candidates := selector.profileCandidates()
		if len(candidates) != tc.want {
			t.Fatalf("mode %s profiles=%d, want %d", tc.mode, len(candidates), tc.want)
		}
		for _, candidate := range candidates {
			if candidate.mode != tc.mode {
				t.Fatalf("mode %s included %s", tc.mode, candidate)
			}
			if candidate.cover.Enabled {
				t.Fatalf("mode %s normal discovery included cover profile %s", tc.mode, candidate)
			}
		}
	}
}

func TestNormalProfilesNeverUseClearPayload(t *testing.T) {
	for _, mode := range []string{WireAuto, WireBinary, WireBP, WireXOR} {
		candidates := (&wireSelector{configured: mode}).profileCandidates()
		if len(candidates) == 0 {
			t.Fatalf("mode %s has no candidates", mode)
		}
		for _, candidate := range candidates {
			if candidate.cover.Clear {
				t.Fatalf("mode %s normal discovery included clear payload profile: %s", mode, candidate)
			}
		}
	}
}

func TestForceClearProfilesTry00Before25WithoutMaskedFallbacks(t *testing.T) {
	selector := &wireSelector{configured: WireAuto, forceClear: true}
	candidates := selector.profileCandidates()
	if len(candidates) != 4 {
		t.Fatalf("force-clear auto profiles=%d, want B00/BP00/B25/BP25", len(candidates))
	}
	wantModes := []string{WireBinary, WireBP, WireBinary, WireBP}
	wantMasks := []byte{0x00, 0x00, 0x25, 0x25}
	for i, candidate := range candidates {
		if candidate.mode != wantModes[i] || candidate.mask != wantMasks[i] {
			t.Fatalf("candidate %d=%s mask=%02x, want mode=%s mask=%02x", i, candidate.mode, candidate.mask, wantModes[i], wantMasks[i])
		}
		if candidate.mode == WireXOR {
			t.Fatalf("force-clear mode included X candidate: %s", candidate)
		}
		if !candidate.cover.Enabled || !candidate.cover.Clear {
			t.Fatalf("force-clear mode included masked/direct candidate: %s", candidate)
		}
		if candidate.cover.HeaderMask != candidate.mask {
			t.Fatalf("candidate %d cover/header mismatch: %+v", i, candidate.cover)
		}
	}
	if candidates[0].cover.ID != 0x0000 || candidates[2].cover.ID != 0x0065 {
		t.Fatalf("unexpected clear profile IDs: 00=%04x 25=%04x", candidates[0].cover.ID, candidates[2].cover.ID)
	}
}

func TestForceClearPinnedFamilyTries00Then25(t *testing.T) {
	for _, mode := range []string{WireBinary, WireBP} {
		candidates := (&wireSelector{configured: mode, forceClear: true}).profileCandidates()
		if len(candidates) != 2 {
			t.Fatalf("mode %s force-clear candidates=%d, want 2", mode, len(candidates))
		}
		if candidates[0].mode != mode || candidates[0].mask != 0x00 || !candidates[0].cover.Clear {
			t.Fatalf("mode %s first forced clear profile is not clear/00: %+v", mode, candidates[0])
		}
		if candidates[1].mode != mode || candidates[1].mask != 0x25 || !candidates[1].cover.Clear {
			t.Fatalf("mode %s second forced clear profile is not clear/25: %+v", mode, candidates[1])
		}
	}
}

func TestForceClearDiscoveryFallsBackFrom00To25(t *testing.T) {
	var seen []byte
	selector := &wireSelector{
		configured:   WireBinary,
		forceClear:   true,
		probeDelay:   time.Nanosecond,
		probeThreads: 1,
		probeOverride: func(choice wireChoice) bool {
			seen = append(seen, choice.mask)
			return choice.mask == 0x25
		},
	}
	choice := selector.mode()
	if choice.mask != 0x25 || !choice.cover.Clear {
		t.Fatalf("selected=%s, want clear mask 25 fallback", choice)
	}
	if len(seen) != 2 || seen[0] != 0x00 || seen[1] != 0x25 {
		t.Fatalf("probe order=%v, want [0 37]", seen)
	}
}

func TestForceClearFailedDiscoveryStillFallsBackToClear00(t *testing.T) {
	selector := &wireSelector{
		configured:        WireAuto,
		forceClear:        true,
		candidateOverride: []wireChoice{{mode: WireBinary}},
		probeDelay:        time.Nanosecond,
		probeOverride:     func(wireChoice) bool { return false },
	}
	choice := selector.mode()
	if !choice.cover.Enabled || !choice.cover.Clear || choice.mode == WireXOR {
		t.Fatalf("force-clear discovery failure fell back to non-clear wire: %s", choice)
	}
	if choice.mask != 0x00 {
		t.Fatalf("force-clear discovery failure did not keep first clear mask 00: %02x", choice.mask)
	}
}

func measureDiscoveryConcurrency(t *testing.T, threads int) int32 {
	t.Helper()
	candidates := make([]wireChoice, 24)
	for i := range candidates {
		candidates[i] = wireChoice{mode: WireBinary, mask: byte(i * 8)}
	}
	var active atomic.Int32
	var maximum atomic.Int32
	var calls atomic.Int32
	selector := &wireSelector{
		configured:        WireAuto,
		candidateOverride: candidates,
		probeThreads:      threads,
		probeDelay:        time.Nanosecond,
		probeOverride: func(wireChoice) bool {
			current := active.Add(1)
			for {
				old := maximum.Load()
				if current <= old || maximum.CompareAndSwap(old, current) {
					break
				}
			}
			calls.Add(1)
			// Keep attempts alive long enough for the globally spaced scheduler
			// to fill every configured worker reliably on slower CI runners.
			time.Sleep(20 * time.Millisecond)
			active.Add(-1)
			return false
		},
	}

	if _, ok := selector.detectLocked(); ok {
		t.Fatal("unexpected working profile")
	}
	if calls.Load() != int32(len(candidates)) {
		t.Fatalf("screened=%d, want %d", calls.Load(), len(candidates))
	}
	return maximum.Load()
}

func TestDiscoveryDefaultsToOneWorker(t *testing.T) {
	if maximum := measureDiscoveryConcurrency(t, 0); maximum != 1 {
		t.Fatalf("maximum concurrent probes=%d, want 1", maximum)
	}
}

func TestDiscoveryHonorsConfiguredWorkers(t *testing.T) {
	if maximum := measureDiscoveryConcurrency(t, 4); maximum != 4 {
		t.Fatalf("maximum concurrent probes=%d, want 4", maximum)
	}
}

func TestFailedManualDiscoveryKeepsPinnedWire(t *testing.T) {
	for _, mode := range []string{WireBinary, WireBP, WireXOR} {
		selector := &wireSelector{
			configured:        mode,
			candidateOverride: []wireChoice{{mode: mode}},
			probeDelay:        time.Nanosecond,
			probeOverride:     func(wireChoice) bool { return false },
		}
		if choice := selector.mode(); choice.mode != mode {
			t.Fatalf("configured=%s fallback=%s", mode, choice.mode)
		}
	}
}
