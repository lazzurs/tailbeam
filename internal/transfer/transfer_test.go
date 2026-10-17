package transfer

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func allow(context.Context, string) error { return nil }

func TestPathValidation(t *testing.T) {
	for _, name := range []string{"../escape", "/absolute", "..", ".", "", `C:\file`, `dir\file`, "bad\nname", "NUL.txt", "COM1", " trailing", "trailing.", "a:b"} {
		if err := validName(name); err == nil {
			t.Errorf("accepted %q", name)
		}
	}
	for _, name := range []string{"normal.txt", "résumé.pdf", "my file.tar.gz"} {
		if err := validName(name); err != nil {
			t.Errorf("%q: %v", name, err)
		}
	}
}

func TestStrictNames(t *testing.T) {
	for _, name := range []string{
		".profile", ".envrc", ".npmrc", ".hidden.txt",
		"a\u202eb.txt", "a\u2066b", "a\u200bb", "a\u00adb", "a\ufeffb", // bidi, zero-width, soft hyphen, BOM
		"a\u0085b", "a\u009fb", "a\x7fb", "a\tb", "a\u00a0b", "a\u2028b",
		"bad\xffutf8", "\xc3",
	} {
		if err := validName(name); err == nil {
			t.Errorf("accepted %q", name)
		}
	}
	for _, name := range []string{"résumé.pdf", "日本語.txt", "a b.tar.gz", "emoji🙂.png", "x.profile"} {
		if err := validName(name); err != nil {
			t.Errorf("%q: %v", name, err)
		}
	}
}

func TestSenderRejectsDotfile(t *testing.T) {
	p := filepath.Join(t.TempDir(), ".envrc")
	if err := os.WriteFile(p, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSenderV2(context.Background(), p, allow, ""); err == nil || !strings.Contains(err.Error(), "dot") {
		t.Fatalf("got %v", err)
	}
}

func TestPreallocateKeepsSizeAndMode(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "x")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := preallocate(f, 1<<20); err != nil {
		t.Fatal(err)
	}
	st, _ := f.Stat()
	if st.Size() != 0 || st.Mode().Perm() != 0600 {
		t.Fatalf("size %d mode %v", st.Size(), st.Mode())
	}
	if err := syncDir(filepath.Dir(f.Name())); err != nil {
		t.Fatal(err)
	}
}
