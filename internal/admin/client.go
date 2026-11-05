package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"syscall"
	"time"

	"github.com/jgermade/intergate/internal/store"
)

// ErrNotRunning means nothing answers on the admin socket.
var ErrNotRunning = errors.New("intergate is not running")

// Client talks to a running server over its admin socket.
type Client struct {
	socket string
	http   *http.Client
}

// NewClient returns a client for the socket at path.
func NewClient(path string) *Client {
	return &Client{
		socket: path,
		http: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", path)
			}},
		},
	}
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://intergate"+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED) {
			return fmt.Errorf("%w (no server on %s)", ErrNotRunning, c.socket)
		}
		if errors.Is(err, os.ErrPermission) {
			return fmt.Errorf("permission denied on %s: run as root or as the intergate user", c.socket)
		}
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		json.NewDecoder(resp.Body).Decode(&e)
		if e.Error == "" {
			e.Error = resp.Status
		}
		return errors.New(e.Error)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// Status returns the server status.
func (c *Client) Status(ctx context.Context) (*Status, error) {
	var s Status
	return &s, c.do(ctx, http.MethodGet, "/v1/status", nil, &s)
}

// Subdomains lists all subdomains.
func (c *Client) Subdomains(ctx context.Context) ([]Subdomain, error) {
	var out []Subdomain
	return out, c.do(ctx, http.MethodGet, "/v1/subdomains", nil, &out)
}

// Subdomain returns a subdomain with its keys.
func (c *Client) Subdomain(ctx context.Context, name string) (*SubdomainDetail, error) {
	var out SubdomainDetail
	return &out, c.do(ctx, http.MethodGet, "/v1/subdomains/"+url.PathEscape(name), nil, &out)
}

// CreateSubdomain registers a subdomain.
func (c *Client) CreateSubdomain(ctx context.Context, req CreateSubdomainRequest) (*Subdomain, KeysResult, error) {
	var out struct {
		Subdomain Subdomain  `json:"subdomain"`
		Keys      KeysResult `json:"keys"`
	}
	err := c.do(ctx, http.MethodPost, "/v1/subdomains", req, &out)
	return &out.Subdomain, out.Keys, err
}

// SetAccess changes who can reach a subdomain.
func (c *Client) SetAccess(ctx context.Context, name string, access store.Access) error {
	return c.do(ctx, http.MethodPost, "/v1/subdomains/"+url.PathEscape(name)+"/access", map[string]store.Access{"access": access}, nil)
}

// AddKeys authorizes SSH keys on a subdomain.
func (c *Client) AddKeys(ctx context.Context, name string, req KeysRequest) (KeysResult, error) {
	var out KeysResult
	return out, c.do(ctx, http.MethodPost, "/v1/subdomains/"+url.PathEscape(name)+"/keys", req, &out)
}

// RemoveKey revokes an SSH key.
func (c *Client) RemoveKey(ctx context.Context, name string, id int64) error {
	return c.do(ctx, http.MethodDelete, fmt.Sprintf("/v1/subdomains/%s/keys/%d", url.PathEscape(name), id), nil, nil)
}

// Disconnect closes a subdomain's tunnel and reports whether it was open.
func (c *Client) Disconnect(ctx context.Context, name string) (bool, error) {
	var out struct {
		Disconnected bool `json:"disconnected"`
	}
	err := c.do(ctx, http.MethodPost, "/v1/subdomains/"+url.PathEscape(name)+"/disconnect", nil, &out)
	return out.Disconnected, err
}

// DeleteSubdomain removes a subdomain.
func (c *Client) DeleteSubdomain(ctx context.Context, name string) error {
	return c.do(ctx, http.MethodDelete, "/v1/subdomains/"+url.PathEscape(name), nil, nil)
}

// Users lists all users.
func (c *Client) Users(ctx context.Context) ([]User, error) {
	var out []User
	return out, c.do(ctx, http.MethodGet, "/v1/users", nil, &out)
}

// CreateUser adds a user.
func (c *Client) CreateUser(ctx context.Context, email string) (*User, error) {
	var out User
	return &out, c.do(ctx, http.MethodPost, "/v1/users", map[string]string{"email": email}, &out)
}

// SetUserDisabled blocks or unblocks a user.
func (c *Client) SetUserDisabled(ctx context.Context, id int64, disabled bool) error {
	verb := "enable"
	if disabled {
		verb = "disable"
	}
	return c.do(ctx, http.MethodPost, fmt.Sprintf("/v1/users/%d/%s", id, verb), nil, nil)
}

// UserKeys lists the SSH keys of an account.
func (c *Client) UserKeys(ctx context.Context, id int64) ([]AccountKey, error) {
	var out []AccountKey
	return out, c.do(ctx, http.MethodGet, fmt.Sprintf("/v1/users/%d/keys", id), nil, &out)
}

// AddUserKeys adds SSH keys to an account.
func (c *Client) AddUserKeys(ctx context.Context, id int64, req KeysRequest) (KeysResult, error) {
	var out KeysResult
	return out, c.do(ctx, http.MethodPost, fmt.Sprintf("/v1/users/%d/keys", id), req, &out)
}

// RemoveUserKey removes a key from an account and from the subdomains it
// was added to, which it returns.
func (c *Client) RemoveUserKey(ctx context.Context, id, key int64) ([]string, error) {
	var out struct {
		RemovedFrom []string `json:"removed_from"`
	}
	err := c.do(ctx, http.MethodDelete, fmt.Sprintf("/v1/users/%d/keys/%d", id, key), nil, &out)
	return out.RemovedFrom, err
}

// SetupURL returns a new link to the dashboard's setup, replacing the
// previous one.
func (c *Client) SetupURL(ctx context.Context) (string, error) {
	var out struct {
		URL string `json:"url"`
	}
	return out.URL, c.do(ctx, http.MethodPost, "/v1/setup/url", nil, &out)
}

// Email describes email delivery.
func (c *Client) Email(ctx context.Context) (*Email, error) {
	var out Email
	return &out, c.do(ctx, http.MethodGet, "/v1/email", nil, &out)
}

// SetEmailPassword changes where the SMTP password comes from.
func (c *Client) SetEmailPassword(ctx context.Context, req PasswordRequest) (*Email, error) {
	var out Email
	return &out, c.do(ctx, http.MethodPut, "/v1/email/password", req, &out)
}
