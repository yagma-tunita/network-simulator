package bridge

import "testing"

func TestImpairRules(t *testing.T) {
	all := newImpair(Options{LossPct: 100, DupPct: 100, Seed: 1}, 1)
	if !all.dropped() {
		t.Fatal("100% loss should drop")
	}
	if !all.duplicated() {
		t.Fatal("100% dup should duplicate")
	}

	none := newImpair(Options{Seed: 2}, 2)
	for i := 0; i < 100; i++ {
		if none.dropped() || none.duplicated() {
			t.Fatal("no impairment should pass")
		}
	}
}
