package auditlog

// RoutingDiff describes the difference between two RoutingConfig values.
// It is used by the routing provider to emit a structured "transition" log
// entry when configuration changes.
type RoutingDiff struct {
	EnginesAdded   []string
	EnginesRemoved []string
	TargetsAdded   map[string][]string
	TargetsRemoved map[string][]string
}

// HasChanges reports whether the diff contains any added or removed entries.
func (d RoutingDiff) HasChanges() bool {
	return len(d.EnginesAdded) > 0 ||
		len(d.EnginesRemoved) > 0 ||
		len(d.TargetsAdded) > 0 ||
		len(d.TargetsRemoved) > 0
}

// DiffRouting computes the set difference between two RoutingConfig values.
// The result is suitable for structured logging.
func DiffRouting(oldCfg, newCfg RoutingConfig) RoutingDiff {
	var diff RoutingDiff
	oldEngines := stringSet(oldCfg.SecretEngines)
	newEngines := stringSet(newCfg.SecretEngines)

	// Engines that appear only in newCfg.
	for _, e := range newCfg.SecretEngines {
		if oldEngines[e] {
			continue
		}
		diff.EnginesAdded = append(diff.EnginesAdded, e)
		if targets := newCfg.Routing[e]; len(targets) > 0 {
			diff.addTarget(e, targets, true)
		}
	}

	// Engines that appear only in oldCfg.
	for _, e := range oldCfg.SecretEngines {
		if newEngines[e] {
			continue
		}
		diff.EnginesRemoved = append(diff.EnginesRemoved, e)
		if targets := oldCfg.Routing[e]; len(targets) > 0 {
			diff.addTarget(e, targets, false)
		}
	}

	// Engines in both configs: diff their target lists.
	for _, e := range newCfg.SecretEngines {
		if !oldEngines[e] {
			continue
		}
		oldTargets := stringSet(oldCfg.Routing[e])
		newTargets := stringSet(newCfg.Routing[e])
		for _, t := range newCfg.Routing[e] {
			if !oldTargets[t] {
				diff.addTarget(e, []string{t}, true)
			}
		}
		for _, t := range oldCfg.Routing[e] {
			if !newTargets[t] {
				diff.addTarget(e, []string{t}, false)
			}
		}
	}
	return diff
}

func (d *RoutingDiff) addTarget(engine string, targets []string, added bool) {
	if added {
		if d.TargetsAdded == nil {
			d.TargetsAdded = make(map[string][]string)
		}
		d.TargetsAdded[engine] = append(d.TargetsAdded[engine], targets...)
		return
	}
	if d.TargetsRemoved == nil {
		d.TargetsRemoved = make(map[string][]string)
	}
	d.TargetsRemoved[engine] = append(d.TargetsRemoved[engine], targets...)
}

func stringSet(s []string) map[string]bool {
	m := make(map[string]bool, len(s))
	for _, v := range s {
		m[v] = true
	}
	return m
}
