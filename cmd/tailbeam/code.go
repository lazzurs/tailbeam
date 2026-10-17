package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/linuskendall/tailbeam/internal/e2e"
)

const codeEnv = "TAILBEAM_CODE"

// receiveTarget parses the receive argument (HOST, HOST:CODE, [IPv6]:CODE or a
// bare CODE) and, in encrypted mode, falls back to TAILBEAM_CODE. fromArgs
// reports a code taken from the command line, which other local users can see.
// A nil code in encrypted mode means the caller must prompt for it.
func receiveTarget(arg string, plaintext bool, getenv func(string) string) (host string, code *e2e.Code, fromArgs bool, err error) {
	host, code, err = e2e.SplitTarget(arg)
	if err != nil {
		return "", nil, false, err
	}
	if plaintext {
		if code != nil {
			return "", nil, false, errors.New("--plaintext transfers have no transfer code; drop the code or --plaintext")
		}
		return host, nil, false, nil
	}
	if code != nil {
		return host, code, true, nil
	}
	if v := getenv(codeEnv); v != "" {
		c, err := e2e.ParseCode(v)
		if err != nil {
			return "", nil, false, fmt.Errorf("%s: %w", codeEnv, err)
		}
		return host, &c, false, nil
	}
	return host, nil, false, nil
}

// promptCode reads the transfer code from the terminal without echo, allowing
// a few attempts for typos (the checksum catches them before any network use).
func promptCode(in *os.File, out io.Writer) (*e2e.Code, error) {
	if !isTerminal(in) {
		return nil, fmt.Errorf("no transfer code: pass SENDER:CODE, set %s, or run receive on a terminal (or use --plaintext on both sides)", codeEnv)
	}
	for range 3 {
		fmt.Fprint(out, "Transfer code: ")
		b, err := term.ReadPassword(int(in.Fd()))
		fmt.Fprintln(out)
		if err != nil {
			return nil, err
		}
		c, err := e2e.ParseCode(strings.TrimSpace(string(b)))
		if err == nil {
			return &c, nil
		}
		fmt.Fprintln(out, err)
	}
	return nil, errors.New("no valid transfer code entered")
}
