package auditlog

import (
	"reflect"
	"sort"
	"testing"
)

func TestDiffRouting_Empty(t *testing.T) {
	t.Parallel()

	cfg := RoutingConfig{
		SecretEngines: []string{"kv", "ssg"},
		Routing: map[string][]string{
			"kv":  {"http://a", "http://b"},
			"ssg": {"http://c"},
		},
	}

	diff := DiffRouting(cfg, cfg)

	if diff.HasChanges() {
		t.Errorf("expected no changes for identical configs, got: %+v", diff)
	}
	if len(diff.EnginesAdded) != 0 || len(diff.EnginesRemoved) != 0 {
		t.Errorf("expected empty engine diffs, got added=%v removed=%v", diff.EnginesAdded, diff.EnginesRemoved)
	}
	if len(diff.TargetsAdded) != 0 || len(diff.TargetsRemoved) != 0 {
		t.Errorf("expected empty target diffs, got added=%v removed=%v", diff.TargetsAdded, diff.TargetsRemoved)
	}
}

func TestDiffRouting_EnginesAdded(t *testing.T) {
	t.Parallel()

	oldCfg := RoutingConfig{
		SecretEngines: []string{"kv"},
		Routing:       map[string][]string{"kv": {"http://a"}},
	}
	newCfg := RoutingConfig{
		SecretEngines: []string{"kv", "ssg", "transit"},
		Routing: map[string][]string{
			"kv":      {"http://a"},
			"ssg":     {"http://b"},
			"transit": {"http://c"},
		},
	}

	got := DiffRouting(oldCfg, newCfg)
	want := RoutingDiff{
		EnginesAdded: []string{"ssg", "transit"},
		TargetsAdded: map[string][]string{
			"ssg":     {"http://b"},
			"transit": {"http://c"},
		},
	}
	if !equalDiff(got, want) {
		t.Errorf("diff mismatch\n got=%+v\nwant=%+v", sortDiff(got), sortDiff(want))
	}
	if !got.HasChanges() {
		t.Errorf("expected HasChanges=true")
	}
}

func TestDiffRouting_EnginesRemoved(t *testing.T) {
	t.Parallel()

	oldCfg := RoutingConfig{
		SecretEngines: []string{"kv", "ssg", "transit"},
		Routing: map[string][]string{
			"kv":      {"http://a"},
			"ssg":     {"http://b"},
			"transit": {"http://c"},
		},
	}
	newCfg := RoutingConfig{
		SecretEngines: []string{"kv"},
		Routing:       map[string][]string{"kv": {"http://a"}},
	}

	got := DiffRouting(oldCfg, newCfg)
	want := RoutingDiff{
		EnginesRemoved: []string{"ssg", "transit"},
		TargetsRemoved: map[string][]string{
			"ssg":     {"http://b"},
			"transit": {"http://c"},
		},
	}
	if !equalDiff(got, want) {
		t.Errorf("diff mismatch\n got=%+v\nwant=%+v", sortDiff(got), sortDiff(want))
	}
}

func TestDiffRouting_TargetsAdded(t *testing.T) {
	t.Parallel()

	oldCfg := RoutingConfig{
		SecretEngines: []string{"kv"},
		Routing:       map[string][]string{"kv": {"http://a"}},
	}
	newCfg := RoutingConfig{
		SecretEngines: []string{"kv"},
		Routing:       map[string][]string{"kv": {"http://a", "http://b", "http://c"}},
	}

	got := DiffRouting(oldCfg, newCfg)
	want := RoutingDiff{
		TargetsAdded: map[string][]string{"kv": {"http://b", "http://c"}},
	}
	if !equalDiff(got, want) {
		t.Errorf("diff mismatch\n got=%+v\nwant=%+v", sortDiff(got), sortDiff(want))
	}
	if !got.HasChanges() {
		t.Errorf("expected HasChanges=true for added target on existing engine")
	}
}

func TestDiffRouting_TargetsRemoved(t *testing.T) {
	t.Parallel()

	oldCfg := RoutingConfig{
		SecretEngines: []string{"kv"},
		Routing:       map[string][]string{"kv": {"http://a", "http://b", "http://c"}},
	}
	newCfg := RoutingConfig{
		SecretEngines: []string{"kv"},
		Routing:       map[string][]string{"kv": {"http://a"}},
	}

	got := DiffRouting(oldCfg, newCfg)
	want := RoutingDiff{
		TargetsRemoved: map[string][]string{"kv": {"http://b", "http://c"}},
	}
	if !equalDiff(got, want) {
		t.Errorf("diff mismatch\n got=%+v\nwant=%+v", sortDiff(got), sortDiff(want))
	}
	if !got.HasChanges() {
		t.Errorf("expected HasChanges=true for removed target on existing engine")
	}
}

// sortDiff makes a RoutingDiff order-independent for comparison.
func sortDiff(d RoutingDiff) RoutingDiff {
	sort.Strings(d.EnginesAdded)
	sort.Strings(d.EnginesRemoved)
	for k := range d.TargetsAdded {
		sort.Strings(d.TargetsAdded[k])
	}
	for k := range d.TargetsRemoved {
		sort.Strings(d.TargetsRemoved[k])
	}
	return d
}

// equalDiff is a small helper for the later cycles in this file.
func equalDiff(a, b RoutingDiff) bool {
	a = sortDiff(a)
	b = sortDiff(b)
	if !reflect.DeepEqual(a.EnginesAdded, b.EnginesAdded) {
		return false
	}
	if !reflect.DeepEqual(a.EnginesRemoved, b.EnginesRemoved) {
		return false
	}
	if !reflect.DeepEqual(a.TargetsAdded, b.TargetsAdded) {
		return false
	}
	if !reflect.DeepEqual(a.TargetsRemoved, b.TargetsRemoved) {
		return false
	}
	return true
}
