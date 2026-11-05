package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/jgermade/intergate/internal/admin"
	"github.com/jgermade/intergate/internal/config"
	"github.com/jgermade/intergate/internal/server"
	"github.com/jgermade/intergate/internal/service"
	"github.com/jgermade/intergate/internal/wildcard"
)

func loadConfig(path string) (*config.Config, error) {
	cfg, err := config.Load(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("no configuration at %s: create one with `intergate config`", path)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

func cmdStart(args []string) error {
	fs, cfgFlag := newFlags("start")
	detached := fs.Bool("detached", false, "run in the background, logging to <data_dir>/intergate.log")
	debug := fs.Bool("debug", false, "enable debug logging")
	if err := fs.Parse(args); err != nil {
		return errQuiet
	}
	path := configPath(*cfgFlag)
	cfg, err := loadConfig(path)
	if err != nil {
		return err
	}
	restrictUmask()
	if *detached {
		return startDetached(path, cfg, *debug)
	}

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	srv, err := server.New(cfg, log, server.Options{Version: version})
	if err != nil {
		return err
	}
	defer srv.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return srv.Run(ctx)
}

// startDetached starts the server in a new session and waits until it
// answers on its admin socket.
func startDetached(path string, cfg *config.Config, debug bool) error {
	if pid := server.RunningPID(cfg); pid != 0 {
		return fmt.Errorf("intergate is already running (PID %d)", pid)
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return err
	}
	logPath := filepath.Join(cfg.DataDir, "intergate.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer logFile.Close()
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	args := []string{"start", "--config", absPath(path)}
	if debug {
		args = append(args, "--debug")
	}
	cmd := exec.Command(exe, args...)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	cmd.SysProcAttr = detachedProcAttr()
	if err := cmd.Start(); err != nil {
		return err
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()

	client := admin.NewClient(cfg.Admin.Socket)
	deadline := time.After(15 * time.Second)
	for {
		select {
		case <-exited:
			fmt.Fprintf(os.Stderr, "intergate exited during startup. Last lines of %s:\n", logPath)
			printTail(os.Stderr, logPath, 15)
			return errQuiet
		case <-deadline:
			return fmt.Errorf("intergate (PID %d) did not become ready in time; see %s", cmd.Process.Pid, logPath)
		case <-time.After(100 * time.Millisecond):
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		st, err := client.Status(ctx)
		cancel()
		if err == nil {
			fmt.Printf("intergate %s started in the background (PID %d)\n", st.Version, st.PID)
			fmt.Printf("  dashboard: %s\n  ssh:       %s\n  logs:      %s\n", st.DashboardURL, st.SSH, logPath)
			fmt.Println("Stop it with `intergate stop`.")
			printSetupLink(client, st, os.Stdout)
			return nil
		}
	}
}

func printTail(w io.Writer, path string, n int) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, sc.Text())
		if len(lines) > n {
			lines = lines[1:]
		}
	}
	for _, l := range lines {
		fmt.Fprintln(w, "  "+l)
	}
}

func cmdStop(args []string, out io.Writer) error {
	fs, cfgFlag := newFlags("stop")
	if err := fs.Parse(args); err != nil {
		return errQuiet
	}
	cfg, err := loadConfig(configPath(*cfgFlag))
	if err != nil {
		return err
	}
	if service.Active() {
		return errors.New("intergate runs as a system service; stop it with `sudo systemctl stop intergate`")
	}
	pid := server.RunningPID(cfg)
	if pid == 0 {
		fmt.Fprintln(out, "intergate is not running")
		return nil
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	if err := p.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("stop PID %d: %w", pid, err)
	}
	for range 100 {
		if server.RunningPID(cfg) == 0 {
			fmt.Fprintf(out, "intergate stopped (PID %d)\n", pid)
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("intergate (PID %d) did not stop within 10s", pid)
}

func cmdStatus(args []string, out io.Writer) error {
	fs, cfgFlag := newFlags("status")
	if err := fs.Parse(args); err != nil {
		return errQuiet
	}
	cfg, err := loadConfig(configPath(*cfgFlag))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := admin.NewClient(cfg.Admin.Socket).Status(ctx)
	if err != nil {
		if pid := server.RunningPID(cfg); pid != 0 {
			return fmt.Errorf("intergate is running (PID %d) but its admin socket does not answer: %w", pid, err)
		}
		if errors.Is(err, admin.ErrNotRunning) {
			fmt.Fprintln(out, "intergate is not running")
			return errQuiet
		}
		return err
	}
	how := "in the foreground or with --detached"
	if service.Active() {
		how = "as a systemd service"
	}
	fmt.Fprintf(out, "intergate %s is running %s (PID %d, up %s)\n", st.Version, how, st.PID, time.Since(st.StartedAt).Round(time.Second))
	fmt.Fprintf(out, "  dashboard:  %s\n  ssh:        %s\n", st.DashboardURL, st.SSH)
	fmt.Fprintf(out, "  subdomains: %d registered, %d online\n  users:      %d\n", st.Subdomains, st.TunnelsOnline, st.Users)
	if st.Setup {
		fmt.Fprintln(out, "  setup:      not done yet: run `intergate setup-url` for the link")
	}
	if c := st.Certificate; c != nil {
		fmt.Fprintln(out, "  tls:        "+certificateLine(c, time.Now()))
	}
	return nil
}

// certificateLine describes the wildcard certificate for `intergate status`.
func certificateLine(c *wildcard.Status, now time.Time) string {
	var line string
	switch {
	case !c.NotAfter.IsZero() && now.Before(c.NotAfter):
		line = fmt.Sprintf("wildcard certificate for %s, valid until %s", strings.Join(c.Names, " and "), c.NotAfter.Local().Format("2006-01-02"))
		if c.Provider != "" {
			line += fmt.Sprintf(", renewed through %s from %s", c.Provider, c.RenewAt.Local().Format("2006-01-02"))
		} else {
			line += " and not renewed: no DNS provider"
		}
	case c.Provider == "":
		return "a certificate for each host; set up a DNS provider in the dashboard (Admin → DNS) for a wildcard one"
	default:
		line = "a certificate for each host, until the wildcard one is issued through " + c.Provider
	}
	switch {
	case c.Issuing:
		line += "\n              issuing: " + strings.ToLower(c.Step[:1]) + c.Step[1:] + "…"
	case c.Error != "":
		line += "\n              failed: " + c.Error
		if !c.NextTry.IsZero() {
			line += fmt.Sprintf(" (trying again in %s)", c.NextTry.Sub(now).Round(time.Second))
		}
	}
	if c.RecordError != "" {
		line += "\n              wildcard record: " + c.RecordError
	}
	return line
}

// printSetupLink prints a link to the dashboard's setup when the server
// st describes is not set up yet.
func printSetupLink(client *admin.Client, st *admin.Status, out io.Writer) {
	if !st.Setup {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	link, err := client.SetupURL(ctx)
	if err != nil {
		fmt.Fprintln(out, "\nIt is not set up yet: `intergate setup-url` gives the link to its setup.")
		return
	}
	fmt.Fprintf(out, "\nFinish the setup in the dashboard, email delivery and the owner, with this link.\n"+
		"It works once; `intergate setup-url` gives a new one.\n\n  %s\n", link)
}

// waitForSetupLink waits for a server that was just started to answer,
// and prints a link to its setup when it needs one.
func waitForSetupLink(client *admin.Client, out io.Writer) {
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		st, err := client.Status(ctx)
		cancel()
		if err == nil {
			printSetupLink(client, st, out)
			return
		}
	}
	fmt.Fprintln(out, "\nIf intergate is not set up yet, `sudo intergate setup-url` gives the link to its setup.")
}

// cmdSetupURL prints a new link to the dashboard's setup: the URL alone on
// stdout, for scripts, and what to do with it on stderr.
func cmdSetupURL(args []string, out io.Writer) error {
	fs, cfgFlag := newFlags("setup-url")
	if err := fs.Parse(args); err != nil {
		return errQuiet
	}
	cfg, err := loadConfig(configPath(*cfgFlag))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	link, err := admin.NewClient(cfg.Admin.Socket).SetupURL(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Open this link to set up email delivery and the owner. It works once, and replaces")
	fmt.Fprintln(os.Stderr, "any link given before; run `intergate setup-url` again for a new one.")
	fmt.Fprintln(out, link)
	return nil
}

func cmdService(args []string, out io.Writer) error {
	fs, cfgFlag := newFlags("service")
	install := fs.Bool("install", false, "install and start the systemd service")
	uninstall := fs.Bool("uninstall", false, "stop and remove the systemd service (keeps config and data)")
	status := fs.Bool("status", false, "show the service status")
	dryRun := fs.Bool("dry-run", false, "print what --install or --uninstall would do without doing it")
	if err := fs.Parse(args); err != nil {
		return errQuiet
	}
	opts := service.Options{Out: out, DryRun: *dryRun}
	switch {
	case *install:
		path := configPath(*cfgFlag)
		if *cfgFlag == "" && os.Getenv("INTERGATE_CONFIG") == "" {
			if _, err := os.Stat(path); err != nil {
				path = systemConfigPath
			}
		}
		opts.ConfigPath = absPath(path)
		if _, err := os.Stat(opts.ConfigPath); err != nil {
			return fmt.Errorf("no configuration at %s: create it first with `sudo intergate config --config %s`", opts.ConfigPath, opts.ConfigPath)
		}
		cfg, err := loadConfig(opts.ConfigPath)
		if err != nil {
			return err
		}
		opts.Config = cfg
		if err := service.Install(opts); err != nil || *dryRun {
			return err
		}
		waitForSetupLink(admin.NewClient(cfg.Admin.Socket), out)
		return nil
	case *uninstall:
		return service.Uninstall(opts)
	case *status:
		return service.Status(out)
	}
	fs.Usage()
	return errQuiet
}

func cmdConfig(args []string) error {
	fs, cfgFlag := newFlags("config")
	accessible := fs.Bool("accessible", false, "plain prompts instead of the full-screen forms (for screen readers and dumb terminals)")
	if err := fs.Parse(args); err != nil {
		return errQuiet
	}
	path := configPath(*cfgFlag)
	return runWizard(path, *accessible || strings.EqualFold(os.Getenv("ACCESSIBLE"), "1"))
}
