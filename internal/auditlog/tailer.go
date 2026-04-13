package auditlog

import (
	"bufio"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// FileTailer tails a file and sends lines to a channel.
type FileTailer struct {
	path    string
	offset  int64
	stopped atomic.Bool
}

// NewFileTailer creates a new FileTailer starting from the given byte offset.
func NewFileTailer(path string, offset int64) (*FileTailer, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	return &FileTailer{
		path:   path,
		offset: offset,
	}, nil
}

// Tail reads lines from the file and sends them to the channel.
// It starts from the configured offset and polls for new content.
// Detects file rotation by checking if the file was replaced (size shrunk or inode changed).
func (ft *FileTailer) Tail(lines chan<- string) {
	f, err := os.Open(ft.path)
	if err != nil {
		return
	}

	if ft.offset > 0 {
		f.Seek(ft.offset, 0)
	}

	scanner := bufio.NewScanner(f)
	for {
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				lines <- line
			}
			ft.offset += int64(len(scanner.Bytes())) + 1
		}

		if ft.stopped.Load() {
			f.Close()
			return
		}

		time.Sleep(100 * time.Millisecond)

		// Get info about our open file handle
		openInfo, openErr := f.Stat()

		// Get info about the path on disk
		pathInfo, pathErr := os.Stat(ft.path)

		rotated := false
		if pathErr != nil {
			// File was removed — wait for it to reappear
			f.Close()
			for i := 0; i < 50; i++ {
				if ft.stopped.Load() {
					return
				}
				time.Sleep(100 * time.Millisecond)
				if _, err := os.Stat(ft.path); err == nil {
					break
				}
			}
			rotated = true
		} else if openErr == nil && !os.SameFile(openInfo, pathInfo) {
			// Inode changed — file was replaced
			f.Close()
			rotated = true
		} else if pathInfo.Size() < ft.offset {
			// File was truncated in place
			f.Close()
			rotated = true
		}

		if rotated {
			ft.offset = 0
			f, err = os.Open(ft.path)
			if err != nil {
				return
			}
			scanner = bufio.NewScanner(f)
			continue
		}

		// Normal case: reopen to pick up appends
		f.Close()
		f, err = os.Open(ft.path)
		if err != nil {
			return
		}
		f.Seek(ft.offset, 0)
		scanner = bufio.NewScanner(f)
	}
}

// Stop signals the tailer to stop reading.
func (ft *FileTailer) Stop() {
	ft.stopped.Store(true)
}

// Offset returns the current byte offset in the file.
func (ft *FileTailer) Offset() int64 {
	return ft.offset
}
