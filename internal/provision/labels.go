package provision

// Contract between the wrangler (which stamps these) and flock (which reads
// them) so the coupling is a compile-time constant rather than a string
// repeated in two binaries.
const (
	LabelManagedBy    = "managedBy"
	ManagedByWrangler = "flock-wrangler"

	AnnoTarget = "flock-wrangler/target"
	AnnoEngine = "flock-wrangler/engine"
)
