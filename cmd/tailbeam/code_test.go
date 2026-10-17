package main

import (
	"context"
	"strings"
	"testing"

	"github.com/linuskendall/tailbeam/internal/e2e"
)

func TestReceiveTarget(t *testing.T) {
	c, _ := e2e.NewCode()
	env := func(v string) func(string) string {
		return func(k string) string {
			if k == codeEnv {
				return v
			}
			return ""
		}
	}
	for _, tc := range []struct {
		arg, env  string
		plaintext bool
		host      string
		code, cli bool
		err       string
	}{
		{arg: "laptop", host: "laptop"},
		{arg: "laptop:" + c.String(), host: "laptop", code: true, cli: true},
		{arg: "[fd7a:115c:a1e0::1]:" + c.String(), host: "fd7a:115c:a1e0::1", code: true, cli: true},
		{arg: "fd7a:115c:a1e0::1", host: "fd7a:115c:a1e0::1"},
		{arg: c.String(), host: "", code: true, cli: true},
		{arg: "laptop", env: c.String(), host: "laptop", code: true},
		{arg: "", env: c.String(), host: "", code: true},
		{arg: "laptop:8784", err: "--port"},
		{arg: "laptop", env: "not-a-code", err: codeEnv},
		{arg: "laptop:" + c.String()[:33] + "x", err: "checksum"},
		{arg: "laptop:" + c.String(), plaintext: true, err: "--plaintext"},
		{arg: "laptop", env: c.String(), plaintext: true, host: "laptop"},
	} {
		host, code, cli, err := receiveTarget(tc.arg, tc.plaintext, env(tc.env))
		if tc.err != "" {
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("%q: want error containing %q, got %v", tc.arg, tc.err, err)
			}
			continue
		}
		if err != nil || host != tc.host || (code != nil) != tc.code || cli != tc.cli {
			t.Errorf("%q env=%q: host=%q code=%v cli=%v err=%v", tc.arg, tc.env, host, code != nil, cli, err)
		}
		if code != nil && *code != c {
			t.Errorf("%q: wrong code", tc.arg)
		}
	}
}

func TestRunValidatesModeAndCodeBeforeNetwork(t *testing.T) {
	t.Setenv(codeEnv, "")
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"send", "--v1", "f", "h"}, "--plaintext"},
		{[]string{"receive", "--yes", "laptop:8784"}, "--port"},
		{[]string{"receive", "--yes", "laptop:aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aaaa"}, "checksum"},
		// No code anywhere and no terminal to prompt on.
		{[]string{"receive", "--yes", "laptop"}, codeEnv},
		{[]string{"receive", "--yes", "--plaintext", "laptop:aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aaaa"}, "checksum"},
	} {
		err := run(context.Background(), tc.args)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: want %q, got %v", tc.args, tc.want, err)
		}
	}
}
