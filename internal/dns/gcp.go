package dns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func init() {
	Register(Spec{
		Name:    "gcp",
		Title:   "Google Cloud DNS",
		Summary: "A service account key, or the server’s own",
		Help: "A service account with the role DNS Administrator (roles/dns.admin) on the project of the zone.\n" +
			"Without a credentials file, Application Default Credentials are used: GOOGLE_APPLICATION_CREDENTIALS,\n" +
			"`gcloud auth application-default login`, or the service account of a GCE VM, GKE (Workload Identity) or Cloud Run.",
		Fields: []Field{
			{Name: "project", Title: "Project ID",
				Description: "The Google Cloud project of the zone. Optional with a service account key or on Google Cloud."},
			{Name: "managed_zone", Title: "Managed zone",
				Description: "The zone's name in Cloud DNS, e.g. example-com. Optional: found from the domain otherwise."},
			{Name: "credentials_json", Title: "Service account key (JSON)", Secret: true, Upload: true,
				Description: "Optional: Application Default Credentials otherwise."},
			{Name: "credentials_file", Title: "Service account key file (JSON)", ConfigOnly: true, Path: true,
				Description: "Optional: Application Default Credentials otherwise."},
		},
		Check: func(o Options) error {
			if o["credentials_json"] != "" && o["credentials_file"] != "" {
				return errors.New("set credentials_json or credentials_file, not both")
			}
			return nil
		},
		New: newGCP,
	})
}

const gcpScope = "https://www.googleapis.com/auth/ndev.clouddns.readwrite"

type gcp struct {
	api      *jsonAPI
	project  string
	zoneName string
	zones    zoneCache
}

func newGCP(o Options, env Env) (Provider, error) {
	// Tokens are fetched long after New returns: the context only carries
	// the HTTP client.
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, env.HTTPClient)
	var creds *google.Credentials
	var err error
	raw, what := []byte(strings.TrimSpace(o["credentials_json"])), "the service account key"
	if file := strings.TrimSpace(o["credentials_file"]); file != "" {
		if raw, err = os.ReadFile(file); err != nil {
			return nil, fmt.Errorf("gcp: %w", err)
		}
		what = file
	}
	if len(raw) > 0 {
		var head struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(raw, &head); err != nil || head.Type == "" {
			return nil, fmt.Errorf("gcp: %s is not a Google Cloud credentials file", what)
		}
		creds, err = google.CredentialsFromJSONWithType(ctx, raw, google.CredentialsType(head.Type), gcpScope)
	} else {
		creds, err = google.FindDefaultCredentials(ctx, gcpScope)
	}
	if err != nil {
		return nil, fmt.Errorf("gcp: %w", err)
	}
	project := strings.TrimSpace(o["project"])
	if project == "" {
		project = creds.ProjectID
	}
	if project == "" {
		return nil, errors.New("gcp: set project: the credentials do not name one")
	}
	ts := creds.TokenSource
	return &gcp{
		project:  project,
		zoneName: strings.TrimSpace(o["managed_zone"]),
		api: &jsonAPI{
			provider: "gcp",
			base:     "https://dns.googleapis.com/dns/v1/projects/" + url.PathEscape(project),
			client:   env.HTTPClient,
			auth: func(r *http.Request) error {
				t, err := ts.Token()
				if err != nil {
					return err
				}
				t.SetAuthHeader(r)
				return nil
			},
			message: func(b []byte) string {
				var r struct {
					Error struct {
						Message string `json:"message"`
					} `json:"error"`
				}
				json.Unmarshal(b, &r)
				return r.Error.Message
			},
		},
	}, nil
}

type gcpRRSet struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	TTL     int      `json:"ttl"`
	Rrdatas []string `json:"rrdatas"`
}

func (g *gcp) zone(ctx context.Context, name string) (string, error) {
	if g.zoneName != "" {
		return g.zoneName, nil
	}
	z, err := g.zones.find(ctx, name, func(ctx context.Context, cand string) (zone, bool, error) {
		var r struct {
			ManagedZones []struct {
				Name       string `json:"name"`
				DNSName    string `json:"dnsName"`
				Visibility string `json:"visibility"`
			} `json:"managedZones"`
		}
		if err := g.api.do(ctx, http.MethodGet, "/managedZones?"+url.Values{"dnsName": {fqdn(cand)}}.Encode(), nil, &r); err != nil {
			return zone{}, false, err
		}
		// A private zone may have the same name: Let's Encrypt only
		// sees the public one.
		for _, z := range r.ManagedZones {
			if Canonical(z.DNSName) == cand && z.Visibility != "private" {
				return zone{ID: z.Name, Name: cand}, true, nil
			}
		}
		return zone{}, false, nil
	})
	return z.ID, err
}

func (g *gcp) rrsetPath(zoneName, name, typ string) string {
	return "/managedZones/" + url.PathEscape(zoneName) + "/rrsets/" + url.PathEscape(fqdn(name)) + "/" + url.PathEscape(typ)
}

func (g *gcp) Set(ctx context.Context, rs RecordSet) error {
	zoneName, err := g.zone(ctx, rs.Name)
	if err != nil {
		return err
	}
	set := gcpRRSet{Name: fqdn(rs.Name), Type: rs.Type, TTL: rs.TTL}
	for _, v := range rs.Values {
		switch rs.Type {
		case "TXT":
			v = quoteTXT(v)
		case "CNAME":
			v = fqdn(v)
		}
		set.Rrdatas = append(set.Rrdatas, v)
	}
	path := g.rrsetPath(zoneName, rs.Name, rs.Type)
	var current gcpRRSet
	switch err := g.api.do(ctx, http.MethodGet, path, nil, &current); {
	case isNotFound(err):
		return g.api.do(ctx, http.MethodPost, "/managedZones/"+url.PathEscape(zoneName)+"/rrsets", set, nil)
	case err != nil:
		return err
	}
	if current.TTL == set.TTL && sameValues(rs.Type, current.Rrdatas, rs.Values) {
		return nil
	}
	return g.api.do(ctx, http.MethodPatch, path, set, nil)
}

func (g *gcp) Delete(ctx context.Context, name, typ string) error {
	zoneName, err := g.zone(ctx, name)
	if err != nil {
		return err
	}
	if err := g.api.do(ctx, http.MethodDelete, g.rrsetPath(zoneName, name, typ), nil, nil); err != nil && !isNotFound(err) {
		return err
	}
	return nil
}

// sameValues reports whether two lists hold the same values, in any order.
func sameValues(typ string, a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for _, v := range a {
		if !containsValue(typ, b, v) {
			return false
		}
	}
	for _, v := range b {
		if !containsValue(typ, a, v) {
			return false
		}
	}
	return true
}
