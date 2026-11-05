package dns

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

func init() {
	Register(Spec{
		Name:    "cloudflare",
		Title:   "Cloudflare",
		Summary: "An API token",
		Help: "An API token (My Profile → API Tokens → Create Token) with the permission Zone → DNS → Edit,\n" +
			"and Zone → Zone → Read unless you give the zone ID, for the zone of the domain.",
		Fields: []Field{
			{Name: "api_token", Title: "API token", Required: true, Secret: true, Env: "CLOUDFLARE_API_TOKEN",
				Description: "With the permission Zone → DNS → Edit on the domain's zone."},
			{Name: "zone_id", Title: "Zone ID",
				Description: "Optional: found from the domain otherwise (that needs Zone → Zone → Read)."},
		},
		New: newCloudflare,
	})
}

type cloudflare struct {
	api    *jsonAPI
	zoneID string
	zones  zoneCache
}

func newCloudflare(o Options, env Env) (Provider, error) {
	token := strings.TrimSpace(o["api_token"])
	return &cloudflare{
		zoneID: strings.TrimSpace(o["zone_id"]),
		api: &jsonAPI{
			provider: "cloudflare",
			base:     "https://api.cloudflare.com/client/v4",
			client:   env.HTTPClient,
			auth: func(r *http.Request) error {
				r.Header.Set("Authorization", "Bearer "+token)
				return nil
			},
			message: func(b []byte) string {
				var r cfResponse
				if json.Unmarshal(b, &r) != nil {
					return ""
				}
				return r.errorText()
			},
		},
	}, nil
}

type cfResponse struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	ResultInfo struct {
		Page       int `json:"page"`
		TotalPages int `json:"total_pages"`
	} `json:"result_info"`
}

func (r cfResponse) errorText() string {
	var msgs []string
	for _, e := range r.Errors {
		msgs = append(msgs, e.Message+" ("+strconv.Itoa(e.Code)+")")
	}
	return strings.Join(msgs, "; ")
}

type cfRecord struct {
	ID      string `json:"id,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied *bool  `json:"proxied,omitempty"`
}

func (c *cloudflare) zone(ctx context.Context, name string) (string, error) {
	if c.zoneID != "" {
		return c.zoneID, nil
	}
	z, err := c.zones.find(ctx, name, func(ctx context.Context, cand string) (zone, bool, error) {
		var r struct {
			cfResponse
			Result []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"result"`
		}
		if err := c.api.do(ctx, http.MethodGet, "/zones?"+url.Values{"name": {cand}}.Encode(), nil, &r); err != nil {
			return zone{}, false, err
		}
		for _, z := range r.Result {
			if Canonical(z.Name) == cand {
				return zone{ID: z.ID, Name: cand}, true, nil
			}
		}
		return zone{}, false, nil
	})
	return z.ID, err
}

// records lists the records of a name and type. The API filters by name
// and type, and so does this, in case it ever matches more.
func (c *cloudflare) records(ctx context.Context, zoneID, name, typ string) ([]cfRecord, error) {
	var out []cfRecord
	for page := 1; ; page++ {
		var r struct {
			cfResponse
			Result []cfRecord `json:"result"`
		}
		q := url.Values{"name": {name}, "type": {typ}, "per_page": {"100"}, "page": {strconv.Itoa(page)}}
		if err := c.api.do(ctx, http.MethodGet, "/zones/"+url.PathEscape(zoneID)+"/dns_records?"+q.Encode(), nil, &r); err != nil {
			return nil, err
		}
		for _, rec := range r.Result {
			if Canonical(rec.Name) == name && strings.EqualFold(rec.Type, typ) {
				out = append(out, rec)
			}
		}
		if page >= r.ResultInfo.TotalPages || page >= 20 {
			return out, nil
		}
	}
}

func (c *cloudflare) Set(ctx context.Context, rs RecordSet) error {
	name := Canonical(rs.Name)
	zoneID, err := c.zone(ctx, name)
	if err != nil {
		return err
	}
	existing, err := c.records(ctx, zoneID, name, rs.Type)
	if err != nil {
		return err
	}
	base := "/zones/" + url.PathEscape(zoneID) + "/dns_records"
	var kept []string
	for _, rec := range existing {
		if !containsValue(rs.Type, rs.Values, rec.Content) || containsValue(rs.Type, kept, rec.Content) {
			if err := c.api.do(ctx, http.MethodDelete, base+"/"+url.PathEscape(rec.ID), nil, nil); err != nil && !isNotFound(err) {
				return err
			}
			continue
		}
		kept = append(kept, rec.Content)
		if rec.TTL != rs.TTL {
			if err := c.api.do(ctx, http.MethodPatch, base+"/"+url.PathEscape(rec.ID), map[string]int{"ttl": rs.TTL}, nil); err != nil {
				return err
			}
		}
	}
	for _, v := range rs.Values {
		if containsValue(rs.Type, kept, v) {
			continue
		}
		rec := cfRecord{Type: rs.Type, Name: name, Content: v, TTL: rs.TTL}
		switch rs.Type {
		case "TXT":
			rec.Content = quoteTXT(v)
		case "A", "AAAA", "CNAME":
			// DNS only: Cloudflare's proxy would not carry SSH or the
			// TCP ports, and would terminate TLS itself.
			rec.Proxied = new(bool)
		}
		if err := c.api.do(ctx, http.MethodPost, base, rec, nil); err != nil {
			return err
		}
		kept = append(kept, v)
	}
	return nil
}

func (c *cloudflare) Delete(ctx context.Context, name, typ string) error {
	name = Canonical(name)
	zoneID, err := c.zone(ctx, name)
	if err != nil {
		return err
	}
	existing, err := c.records(ctx, zoneID, name, typ)
	if err != nil {
		return err
	}
	for _, rec := range existing {
		if err := c.api.do(ctx, http.MethodDelete, "/zones/"+url.PathEscape(zoneID)+"/dns_records/"+url.PathEscape(rec.ID), nil, nil); err != nil && !isNotFound(err) {
			return err
		}
	}
	return nil
}
