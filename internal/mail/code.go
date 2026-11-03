package mail

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/idna"
)

//go:embed code.html
var codeHTML string

var codeTemplate = template.Must(template.New("code").Parse(codeHTML))

// Code is an email that carries a one-time code: for signing in, finishing
// the setup, or confirming a new SMTP relay.
//
// Mail apps offer to copy such codes (Gmail's "Copy code", iOS and macOS
// AutoFill) when they find them: the code leads the subject, comes right
// after the first sentence of the text, and stands alone in the HTML,
// digits only, never split by spaces or markup.
//
// It also goes in an OTP-Token header field, bound to the dashboard's
// origin (see OTPToken), for a mail app or browser that hands a code only
// to the page it is for, so a look-alike site cannot ask for it.
type Code struct {
	To   string
	Code string
	// Subject follows the code: "123456 is your intergate sign-in code".
	Subject string
	Heading string
	Intro   string
	// Details are label and value rows under the code, like the settings
	// a code confirms.
	Details [][2]string
	TTL     time.Duration
	// Note says what to do with an email nobody asked for.
	Note string
	// Site is the dashboard's URL, in the footer.
	Site string
}

// Message renders c as plain text and HTML.
func (c Code) Message() Message {
	minutes := int(c.TTL.Round(time.Minute).Minutes())
	host := c.Site
	if u, err := url.Parse(c.Site); err == nil && u.Host != "" {
		host = u.Host
	}
	subject := c.Code + " " + c.Subject

	var text strings.Builder
	fmt.Fprintf(&text, "%s\n\n%s\n\n    %s\n\nIt expires in %d minutes and works once.\n", c.Heading, c.Intro, c.Code, minutes)
	if len(c.Details) > 0 {
		text.WriteString("\n")
		width := 0
		for _, d := range c.Details {
			width = max(width, len(d[0]))
		}
		for _, d := range c.Details {
			fmt.Fprintf(&text, "  %-*s  %s\n", width+1, d[0]+":", d[1])
		}
	}
	fmt.Fprintf(&text, "\n%s\n\n-- \nintergate at %s\n", c.Note, c.Site)

	var html bytes.Buffer
	err := codeTemplate.Execute(&html, map[string]any{
		"Title":     subject,
		"Preheader": fmt.Sprintf("%s is your code. It expires in %d minutes.", c.Code, minutes),
		"Heading":   c.Heading,
		"Intro":     c.Intro,
		"Code":      c.Code,
		"Minutes":   minutes,
		"Details":   c.Details,
		"Note":      c.Note,
		"Site":      c.Site,
		"Host":      host,
	})
	if err != nil {
		panic(err) // a fixed template with plain strings
	}
	m := Message{To: c.To, Subject: subject, Body: text.String(), HTML: html.String()}
	if token := OTPToken(c.Code, c.Site); token != "" {
		m.Header = append(m.Header, [2]string{"OTP-Token", token})
	}
	return m
}

// OTPToken is the value of the OTP-Token header field that carries code to
// the page at site, as draft-goto-otp-token-00 has it: the code, a
// Structured Field string, bound to the page's origin.
//
//	OTP-Token: "123456"; origin="https://gate.example.com"
//
// The origin is in its canonical form: lower case, ASCII (an international
// name in punycode), with no default port. It is "" when site has no
// origin a code may be bound to: the draft takes only a potentially
// trustworthy one, on https, or on http on this machine (localhost,
// *.localhost, a loopback address).
func OTPToken(code, site string) string {
	origin := originOf(site)
	if origin == "" || code == "" {
		return ""
	}
	c, ok := sfString(code)
	if !ok {
		return ""
	}
	o, _ := sfString(origin)
	return c + "; origin=" + o
}

// originOf is the ASCII serialization of site's origin, if it is
// potentially trustworthy, or "".
func originOf(site string) string {
	u, err := url.Parse(site)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	local := host == "localhost" || strings.HasSuffix(host, ".localhost")
	if ip := net.ParseIP(host); ip != nil {
		local = ip.IsLoopback()
		host = ip.String()
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
	} else if host, err = idna.Lookup.ToASCII(host); err != nil {
		return ""
	}
	port := u.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return ""
		}
		port = strconv.Itoa(n)
	}
	switch {
	case scheme == "https":
		if port == "443" {
			port = ""
		}
	case scheme == "http" && local:
		if port == "80" {
			port = ""
		}
	default:
		return ""
	}
	if port != "" {
		host += ":" + port
	}
	return scheme + "://" + host
}

// sfString is s as a Structured Field string (RFC 8941): quoted, with \ and
// " escaped. Only printable ASCII can be one.
func sfString(s string) (string, bool) {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e {
			return "", false
		}
		if c == '"' || c == '\\' {
			b.WriteByte('\\')
		}
		b.WriteByte(c)
	}
	b.WriteByte('"')
	return b.String(), true
}
