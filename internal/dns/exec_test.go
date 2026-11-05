package dns

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestExec(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script")
	}
	dir := t.TempDir()
	log := filepath.Join(dir, "calls")
	script := filepath.Join(dir, "hook.sh")
	os.WriteFile(script, []byte("#!/bin/sh\n"+
		"[ \"$3\" = FAIL ] && { echo 'zone is locked' >&2; exit 3; }\n"+
		"echo \"$@\" >> "+log+"\n"), 0o755)

	p, err := New("exec", Options{"command": script}, Env{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := p.Set(ctx, RecordSet{Name: "_acme-challenge.Gate.Example.com.", Type: "TXT", TTL: 60, Values: []string{"v1", "v2"}}); err != nil {
		t.Fatal(err)
	}
	if err := p.Delete(ctx, "_acme-challenge.gate.example.com", "TXT"); err != nil {
		t.Fatal(err)
	}
	calls, _ := os.ReadFile(log)
	want := "set _acme-challenge.gate.example.com TXT 60 v1 v2\ndelete _acme-challenge.gate.example.com TXT\n"
	if string(calls) != want {
		t.Errorf("calls:\n%s\nwant\n%s", calls, want)
	}
	err = p.Delete(ctx, "x.example.com", "FAIL")
	if err == nil || !strings.Contains(err.Error(), "exit status 3: zone is locked") {
		t.Errorf("failure: %v", err)
	}

	os.WriteFile(filepath.Join(dir, "plain"), []byte("x"), 0o644)
	if _, err := New("exec", Options{"command": filepath.Join(dir, "plain")}, Env{}); err == nil {
		t.Error("a file that is not executable accepted")
	}
}
