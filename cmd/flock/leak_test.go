package main

import (
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m,
		// signal.NotifyContext spawns a goroutine that lingers after run() returns
		// because the os/signal package keeps a global watcher. It is not a leak
		// in production (process exits) but goleak flags it. Ignore it.
		goleak.IgnoreTopFunction("os/signal.signal_recv"),
		goleak.IgnoreTopFunction("os/signal.loop"),
		goleak.IgnoreAnyFunction("net/http.(*Server).Shutdown"),
	)
}
