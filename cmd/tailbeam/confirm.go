package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// isTerminal reports whether f is an interactive terminal.
func isTerminal(f *os.File) bool { return term.IsTerminal(int(f.Fd())) }

// accept shows what is about to be downloaded and reads one line of consent.
// Only "y" or "yes" (any case) accepts; EOF and everything else decline. The
// read runs in a goroutine so cancellation (Ctrl-C) is not blocked on stdin.
func accept(ctx context.Context, in io.Reader, out io.Writer, sender, id, name string, size int64) (bool, error) {
	fmt.Fprintf(out, "Sender: %q [%s]\nFile:   %q\nSize:   %d bytes\nAccept? [y/N] ", sender, id, name, size)
	type result struct {
		line string
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		line, err := bufio.NewReader(io.LimitReader(in, 1024)).ReadString('\n')
		ch <- result{line, err}
	}()
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case r := <-ch:
		if r.err != nil && !errors.Is(r.err, io.EOF) {
			return false, r.err
		}
		a := strings.ToLower(strings.TrimSpace(r.line))
		return a == "y" || a == "yes", nil
	}
}
