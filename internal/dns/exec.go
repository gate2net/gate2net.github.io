package dns

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func init() {
	Register(Spec{
		Name:       "exec",
		Title:      "A program of yours (any other DNS service)",
		ConfigOnly: true,
		Help: "intergate runs the program with the change to make, for any DNS service:\n" +
			"  PROGRAM set NAME TYPE TTL VALUE...   replace the records of NAME and TYPE with these values\n" +
			"  PROGRAM delete NAME TYPE             remove them\n" +
			"NAME is fully qualified without the final dot, TXT values come unquoted, and the program\n" +
			"gets intergate's environment. It exits with 0 once the change is made.",
		Fields: []Field{
			{Name: "command", Title: "Program", Required: true, Path: true,
				Description: "Path to an executable, e.g. /etc/intergate/dns-hook.sh."},
			{Name: "timeout", Title: "Timeout",
				Description: "How long a change may take. Default 2m."},
		},
		Check: func(o Options) error {
			if t := o["timeout"]; t != "" {
				if d, err := time.ParseDuration(t); err != nil || d <= 0 {
					return fmt.Errorf("timeout must be a duration like 2m, not %q", t)
				}
			}
			return nil
		},
		New: newExec,
	})
}

type execProvider struct {
	command string
	timeout time.Duration
	env     Env
}

func newExec(o Options, env Env) (Provider, error) {
	p := &execProvider{command: strings.TrimSpace(o["command"]), timeout: 2 * time.Minute, env: env}
	if t := o["timeout"]; t != "" {
		p.timeout, _ = time.ParseDuration(t)
	}
	if fi, err := os.Stat(p.command); err != nil {
		return nil, fmt.Errorf("exec: %w", err)
	} else if fi.IsDir() || runtime.GOOS != "windows" && fi.Mode().Perm()&0o111 == 0 {
		return nil, fmt.Errorf("exec: %s is not an executable file", p.command)
	}
	return p, nil
}

func (p *execProvider) run(ctx context.Context, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, p.command, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.WaitDelay = 5 * time.Second
	err := cmd.Run()
	if out := strings.TrimSpace(stdout.String()); out != "" {
		p.env.Log.Debug("dns program", "args", strings.Join(args, " "), "output", out)
	}
	if err == nil {
		return nil
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		err = fmt.Errorf("took more than %s", p.timeout)
	}
	msg := strings.TrimSpace(stderr.String())
	if len(msg) > 500 {
		msg = "…" + msg[len(msg)-500:]
	}
	if msg != "" {
		return fmt.Errorf("exec: %s %s: %v: %s", p.command, args[0], err, msg)
	}
	return fmt.Errorf("exec: %s %s: %v", p.command, args[0], err)
}

func (p *execProvider) Set(ctx context.Context, rs RecordSet) error {
	return p.run(ctx, append([]string{"set", Canonical(rs.Name), rs.Type, strconv.Itoa(rs.TTL)}, rs.Values...)...)
}

func (p *execProvider) Delete(ctx context.Context, name, typ string) error {
	return p.run(ctx, "delete", Canonical(name), typ)
}
