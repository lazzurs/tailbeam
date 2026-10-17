package main

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"
)

func TestAccept(t *testing.T) {
	for in, want := range map[string]bool{"y\n": true, "YES\n": true, " yes \n": true, "y": true, "n\n": false, "\n": false, "": false, "yep\n": false, "no\ny\n": false} {
		var out bytes.Buffer
		got, err := accept(context.Background(), strings.NewReader(in), &out, "host.ts.net.", "nXYZ", "a\nb.txt", 42)
		if err != nil || got != want {
			t.Errorf("%q: got %v, %v", in, got, err)
		}
		for _, s := range []string{`"host.ts.net."`, "[nXYZ]", `"a\nb.txt"`, "42 bytes", "Accept? [y/N]"} {
			if !strings.Contains(out.String(), s) {
				t.Errorf("%q: prompt missing %s: %q", in, s, out.String())
			}
		}
	}
}

func TestAcceptCancel(t *testing.T) {
	pr, pw := io.Pipe()
	defer pw.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if ok, err := accept(ctx, pr, io.Discard, "h", "id", "f", 1); ok || err == nil {
		t.Fatalf("got %v, %v", ok, err)
	}
}

func TestRunRefusesWithoutTerminalOrYes(t *testing.T) {
	// Under `go test` stdin is not a terminal.
	err := run(context.Background(), []string{"receive"})
	if err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("got %v", err)
	}
}
