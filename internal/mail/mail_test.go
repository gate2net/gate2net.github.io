package mail

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"net"
	stdmail "net/mail"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jgermade/intergate/internal/config"
)

// fakeSMTP accepts one message and records the conversation.
type fakeSMTP struct {
	addr     string
	auth     chan string
	envelope chan [2]string
	data     chan string
}

func newFakeSMTP(t *testing.T) *fakeSMTP {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	f := &fakeSMTP{addr: ln.Addr().String(), auth: make(chan string, 1), envelope: make(chan [2]string, 1), data: make(chan string, 1)}
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		say := func(s string) { io.WriteString(c, s+"\r\n") }
		say("220 fake ESMTP")
		var from string
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			cmd := strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(cmd, "EHLO"):
				say("250-fake")
				say("250 AUTH PLAIN")
			case strings.HasPrefix(cmd, "AUTH PLAIN "):
				dec, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(cmd, "AUTH PLAIN "))
				f.auth <- string(dec)
				if strings.HasSuffix(string(dec), "\x00wrong") {
					say("535 5.7.8 authentication failed")
				} else {
					say("235 ok")
				}
			case strings.HasPrefix(cmd, "MAIL FROM:"):
				from = cmd
				say("250 ok")
			case strings.HasPrefix(cmd, "RCPT TO:"):
				f.envelope <- [2]string{from, cmd}
				say("250 ok")
			case cmd == "DATA":
				say("354 go")
				var b strings.Builder
				for {
					l, err := r.ReadString('\n')
					if err != nil || l == ".\r\n" {
						break
					}
					b.WriteString(l)
				}
				f.data <- b.String()
				say("250 queued")
			case cmd == "QUIT":
				say("221 bye")
				return
			default:
				say("250 ok")
			}
		}
	}()
	return f
}

func TestSMTPSender(t *testing.T) {
	f := newFakeSMTP(t)
	host, port, _ := net.SplitHostPort(f.addr)
	p, _ := strconv.Atoi(port)
	s := New(config.EmailConfig{
		From: "intergate <no-reply@gate.example.com>",
		SMTP: config.SMTPConfig{Host: host, Port: p, TLS: "none", Username: "user", Password: "pw"},
	}, nil)
	err := s.Send(context.Background(), Message{To: "alice@example.com", Subject: "Your code: 123456", Body: "Code:\n\n    123456\n"})
	if err != nil {
		t.Fatal(err)
	}
	if got := <-f.auth; got != "\x00user\x00pw" {
		t.Errorf("AUTH PLAIN = %q", got)
	}
	if env := <-f.envelope; env[0] != "MAIL FROM:<no-reply@gate.example.com>" || env[1] != "RCPT TO:<alice@example.com>" {
		t.Errorf("envelope = %q", env)
	}
	msg, err := stdmail.ReadMessage(strings.NewReader(<-f.data))
	if err != nil {
		t.Fatal(err)
	}
	if msg.Header.Get("Subject") != "Your code: 123456" || msg.Header.Get("To") != "<alice@example.com>" || msg.Header.Get("Message-Id") == "" {
		t.Errorf("headers = %v", msg.Header)
	}
	body, _ := io.ReadAll(msg.Body)
	if !strings.Contains(string(body), "    123456") {
		t.Errorf("body = %q", body)
	}
}

func TestCheck(t *testing.T) {
	smtpConfig := func(addr, password string) config.SMTPConfig {
		host, port, _ := net.SplitHostPort(addr)
		p, _ := strconv.Atoi(port)
		return config.SMTPConfig{Host: host, Port: p, TLS: "none", Username: "user", Password: password}
	}
	f := newFakeSMTP(t)
	if err := Check(context.Background(), smtpConfig(f.addr, "pw")); err != nil {
		t.Fatal(err)
	}
	if got := <-f.auth; got != "\x00user\x00pw" {
		t.Errorf("AUTH PLAIN = %q", got)
	}
	select {
	case env := <-f.envelope:
		t.Errorf("Check sent a message: %q", env)
	default:
	}

	f = newFakeSMTP(t)
	if err := Check(context.Background(), smtpConfig(f.addr, "wrong")); err == nil || !strings.Contains(err.Error(), "authenticate") {
		t.Errorf("wrong password: %v", err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := ln.Addr().String()
	ln.Close()
	if err := Check(context.Background(), smtpConfig(closed, "pw")); err == nil || !strings.Contains(err.Error(), "connect") {
		t.Errorf("nothing listening: %v", err)
	}
}

func TestCodeMessage(t *testing.T) {
	m := Code{
		To:      "owner@example.com",
		Code:    "042137",
		Subject: "is your intergate sign-in code",
		Heading: "Your sign-in code",
		Intro:   "Enter it to sign in to intergate at gate.example.com.",
		Details: [][2]string{{"Server", "smtp.example.com:587"}, {"Sender", "intergate <no-reply@example.com>"}},
		TTL:     10 * time.Minute,
		Note:    "If you did not try to sign in, ignore this email.",
		Site:    "https://gate.example.com/",
	}.Message()
	if m.Subject != "042137 is your intergate sign-in code" || m.To != "owner@example.com" {
		t.Errorf("subject %q to %q", m.Subject, m.To)
	}
	for _, want := range []string{"Your sign-in code\n\nEnter it", "\n    042137\n", "expires in 10 minutes", "Sender:  intergate <no-reply@example.com>", "intergate at https://gate.example.com/"} {
		if !strings.Contains(m.Body, want) {
			t.Errorf("text lacks %q:\n%s", want, m.Body)
		}
	}
	// The code stands alone in its element, and values are escaped.
	for _, want := range []string{">042137</div>", "042137 is your code.", "&lt;no-reply@example.com&gt;", `href="https://gate.example.com/"`, ">gate.example.com</a>"} {
		if !strings.Contains(m.HTML, want) {
			t.Errorf("HTML lacks %q", want)
		}
	}

	raw := Compose(&stdmail.Address{Name: "intergate", Address: "no-reply@example.com"}, &stdmail.Address{Address: m.To}, m)
	msg, err := stdmail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/alternative" {
		t.Fatalf("Content-Type %q: %v", msg.Header.Get("Content-Type"), err)
	}
	if got := msg.Header.Get("Subject"); got != m.Subject {
		t.Errorf("Subject header %q", got)
	}
	if got := msg.Header["Otp-Token"]; len(got) != 1 || got[0] != `"042137"; origin="https://gate.example.com"` {
		t.Errorf("OTP-Token header %q", got)
	}
	parts := multipart.NewReader(msg.Body, params["boundary"])
	for _, want := range []struct{ typ, body string }{{"text/plain; charset=utf-8", m.Body}, {"text/html; charset=utf-8", m.HTML}} {
		p, err := parts.NextPart()
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(p)
		if p.Header.Get("Content-Type") != want.typ || strings.ReplaceAll(string(body), "\r\n", "\n") != want.body {
			t.Errorf("part %s:\n%s", p.Header.Get("Content-Type"), body)
		}
	}
	if _, err := parts.NextPart(); err != io.EOF {
		t.Errorf("more parts: %v", err)
	}
}

func TestOTPToken(t *testing.T) {
	for _, c := range []struct{ site, want string }{
		{"https://gate.example.com/", `"042137"; origin="https://gate.example.com"`},
		// The canonical origin: lower case, no default port, no path.
		{"HTTPS://Gate.Example.COM:443/login?rd=/", `"042137"; origin="https://gate.example.com"`},
		{"https://gate.example.com:8443/", `"042137"; origin="https://gate.example.com:8443"`},
		{"https://bücher.example/", `"042137"; origin="https://xn--bcher-kva.example"`},
		// Plain http only on this machine.
		{"http://localhost:8080/", `"042137"; origin="http://localhost:8080"`},
		{"http://gate.localhost:80/", `"042137"; origin="http://gate.localhost"`},
		{"http://127.0.0.1:18080/", `"042137"; origin="http://127.0.0.1:18080"`},
		{"http://[::1]:8080/", `"042137"; origin="http://[::1]:8080"`},
		{"http://gate.example.com/", ""},
		{"http://10.0.0.1/", ""},
		{"ftp://gate.example.com/", ""},
		{"", ""},
		{"/relative", ""},
	} {
		if got := OTPToken("042137", c.site); got != c.want {
			t.Errorf("OTPToken(%q) = %q, want %q", c.site, got, c.want)
		}
	}
	// What a Structured Field string cannot hold is not sent.
	if got := OTPToken("04\n2137", "https://gate.example.com/"); got != "" {
		t.Errorf("a code with a line break: %q", got)
	}
	if got := OTPToken(`4"2`, "https://gate.example.com/"); got != `"4\"2"; origin="https://gate.example.com"` {
		t.Errorf("a quote: %q", got)
	}

	// Plain http elsewhere: no header at all.
	m := Code{To: "a@example.com", Code: "042137", Subject: "is your code", TTL: time.Minute, Site: "http://gate.example.com/"}.Message()
	if len(m.Header) != 0 {
		t.Errorf("header for an http site: %q", m.Header)
	}
}
