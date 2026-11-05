package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// jsonAPI calls a provider's JSON API.
type jsonAPI struct {
	provider string
	base     string
	client   *http.Client
	// auth adds credentials to a request.
	auth func(*http.Request) error
	// message reads the error message of a failed answer's body.
	message func(body []byte) string
}

func (a *jsonAPI) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if a.auth != nil {
		if err := a.auth(req); err != nil {
			return fmt.Errorf("%s: %w", a.provider, err)
		}
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("%s: %w", a.provider, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return fmt.Errorf("%s: %w", a.provider, err)
	}
	if resp.StatusCode/100 != 2 {
		msg := ""
		if a.message != nil {
			msg = a.message(raw)
		}
		if msg == "" {
			msg = strings.TrimSpace(string(raw))
			if len(msg) > 200 {
				msg = msg[:200] + "…"
			}
		}
		return &apiError{Provider: a.provider, Status: resp.StatusCode, Message: msg}
	}
	if out == nil || len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("%s: unexpected answer: %w", a.provider, err)
	}
	return nil
}
