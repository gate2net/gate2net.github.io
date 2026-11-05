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
		Name:    "digitalocean",
		Title:   "DigitalOcean",
		Summary: "A personal access token",
		Help:    "A personal access token (API → Tokens) with read and write access to domains.",
		Fields: []Field{
			{Name: "api_token", Title: "API token", Required: true, Secret: true, Env: "DIGITALOCEAN_TOKEN",
				Description: "With the scopes domain:read, domain:create, domain:update and domain:delete."},
			{Name: "domain", Title: "Domain",
				Description: "The domain as DigitalOcean has it, e.g. example.com. Optional: found otherwise."},
		},
		New: newDigitalOcean,
	})
}

type digitalOcean struct {
	api   *jsonAPI
	zone  string
	zones zoneCache
}

func newDigitalOcean(o Options, env Env) (Provider, error) {
	token := strings.TrimSpace(o["api_token"])
	return &digitalOcean{
		zone: Canonical(o["domain"]),
		api: &jsonAPI{
			provider: "digitalocean",
			base:     "https://api.digitalocean.com/v2",
			client:   env.HTTPClient,
			auth: func(r *http.Request) error {
				r.Header.Set("Authorization", "Bearer "+token)
				return nil
			},
			message: func(b []byte) string {
				var r struct {
					Message string `json:"message"`
				}
				json.Unmarshal(b, &r)
				return r.Message
			},
		},
	}, nil
}

type doRecord struct {
	ID   int    `json:"id,omitempty"`
	Type string `json:"type"`
	Name string `json:"name"`
	Data string `json:"data"`
	TTL  int    `json:"ttl"`
}

func (d *digitalOcean) domain(ctx context.Context, name string) (string, error) {
	if d.zone != "" {
		return d.zone, nil
	}
	z, err := d.zones.find(ctx, name, func(ctx context.Context, cand string) (zone, bool, error) {
		err := d.api.do(ctx, http.MethodGet, "/domains/"+url.PathEscape(cand), nil, nil)
		if isNotFound(err) {
			return zone{}, false, nil
		}
		return zone{ID: cand, Name: cand}, err == nil, err
	})
	return z.ID, err
}

func (d *digitalOcean) records(ctx context.Context, zoneName, name, typ string) ([]doRecord, error) {
	var out []doRecord
	rel := relative(name, zoneName)
	for page := 1; page <= 20; page++ {
		var r struct {
			Records []doRecord `json:"domain_records"`
			Links   struct {
				Pages struct {
					Next string `json:"next"`
				} `json:"pages"`
			} `json:"links"`
		}
		q := url.Values{"name": {name}, "type": {typ}, "per_page": {"200"}, "page": {strconv.Itoa(page)}}
		if err := d.api.do(ctx, http.MethodGet, "/domains/"+url.PathEscape(zoneName)+"/records?"+q.Encode(), nil, &r); err != nil {
			return nil, err
		}
		for _, rec := range r.Records {
			if strings.EqualFold(rec.Name, rel) && strings.EqualFold(rec.Type, typ) {
				out = append(out, rec)
			}
		}
		if r.Links.Pages.Next == "" {
			break
		}
	}
	return out, nil
}

func (d *digitalOcean) Set(ctx context.Context, rs RecordSet) error {
	name := Canonical(rs.Name)
	zoneName, err := d.domain(ctx, name)
	if err != nil {
		return err
	}
	existing, err := d.records(ctx, zoneName, name, rs.Type)
	if err != nil {
		return err
	}
	base := "/domains/" + url.PathEscape(zoneName) + "/records"
	var kept []string
	for _, rec := range existing {
		path := base + "/" + strconv.Itoa(rec.ID)
		if !containsValue(rs.Type, rs.Values, rec.Data) || containsValue(rs.Type, kept, rec.Data) {
			if err := d.api.do(ctx, http.MethodDelete, path, nil, nil); err != nil && !isNotFound(err) {
				return err
			}
			continue
		}
		kept = append(kept, rec.Data)
		if rec.TTL != max(rs.TTL, 30) {
			if err := d.api.do(ctx, http.MethodPatch, path, map[string]any{"type": rs.Type, "ttl": max(rs.TTL, 30)}, nil); err != nil {
				return err
			}
		}
	}
	for _, v := range rs.Values {
		if containsValue(rs.Type, kept, v) {
			continue
		}
		if rs.Type == "CNAME" {
			v = fqdn(v)
		}
		rec := doRecord{Type: rs.Type, Name: relative(name, zoneName), Data: v, TTL: max(rs.TTL, 30)}
		if err := d.api.do(ctx, http.MethodPost, base, rec, nil); err != nil {
			return err
		}
		kept = append(kept, v)
	}
	return nil
}

func (d *digitalOcean) Delete(ctx context.Context, name, typ string) error {
	name = Canonical(name)
	zoneName, err := d.domain(ctx, name)
	if err != nil {
		return err
	}
	existing, err := d.records(ctx, zoneName, name, typ)
	if err != nil {
		return err
	}
	for _, rec := range existing {
		if err := d.api.do(ctx, http.MethodDelete, "/domains/"+url.PathEscape(zoneName)+"/records/"+strconv.Itoa(rec.ID), nil, nil); err != nil && !isNotFound(err) {
			return err
		}
	}
	return nil
}
