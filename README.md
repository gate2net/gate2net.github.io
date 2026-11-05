# intergate

**[jgermade.github.io/intergate](https://jgermade.github.io/intergate/)** ·
[releases](https://github.com/jgermade/intergate/releases)

```sh
curl -fsSL https://jgermade.github.io/intergate/setup.sh | sh
```

Expose local HTTP services on your own domain through SSH, like
[sish](https://github.com/antoniomika/sish) or ngrok, managed from a web
dashboard or an interactive terminal wizard.

```bash
ssh -p 2222 -R myapp:80:localhost:3000 gate.example.com
# → https://myapp.gate.example.com now serves your localhost:3000
```

- **Subdomains and SSH keys are registered in the dashboard** (or with
  `intergate config`). Each subdomain has its own authorized SSH keys: a key
  can only open tunnels on the subdomains it was added to, and unknown keys
  are rejected during the SSH handshake.
- **Sign-in without passwords:** a one-time code sent by email, then
  passkeys (fingerprint, face or device PIN). GitHub and any OpenID Connect
  provider can be added as optional sign-in methods.
- **Access control per subdomain:** *public*, *signed-in users* or *private*
  (owner only). Protected tunnels send visitors to sign in and work with any
  app behind them; the app never sees intergate's cookies.
- **Live view** of every tunnel: client address, key, requests and traffic,
  with a disconnect button. Removing a key or disabling a user closes their
  tunnels at once. The SSH session prints every request, like sish.
- **TCP and UDP ports** for databases, SSH, game servers…: each subdomain
  can get public ports of its own (`tcp://gate.example.com:30042`), open
  only to the addresses you allow. UDP goes through the `intergate tunnel`
  client, which runs without installing anything.
- **Single static binary** with SQLite storage and automatic HTTPS (Let's
  Encrypt) — or Docker, or Kubernetes with Traefik.
- **One wildcard certificate** for every subdomain, through your DNS
  provider's API — Cloudflare, Google Cloud DNS, Amazon Route 53,
  DigitalOcean, or a program of yours for any other — set up from the
  dashboard's Admin page once intergate runs.

## How it works

```
 browser ──HTTPS──▶ intergate ──SSH channel──▶ ssh -R client ──▶ localhost:3000
                     │  myapp.gate.example.com → tunnel "myapp"
                     │  gate.example.com       → dashboard
```

The dashboard is served on the host of `public_url`; every direct subdomain
of it is a tunnel. When a client runs `ssh -R myapp:80:localhost:3000`,
intergate checks that the key is authorized for `myapp` and routes
`myapp.<domain>` to that SSH connection. Each HTTP request (WebSockets and
streaming included) opens a channel back to the client.

The `80` only tells intergate that this is an HTTP tunnel: OpenSSH requires
a port there. The subdomain can also come from the SSH user name, or be left
out when the key belongs to a single subdomain:

```bash
ssh -p 2222 -R 80:localhost:3000 myapp@gate.example.com
ssh -p 2222 -R 80:localhost:3000 gate.example.com
```

A new connection for a subdomain replaces the previous one, so reconnecting
(e.g. with `autossh -M 0`) takes over at once.

### TCP ports

With `tcp.ports` in the configuration, a subdomain can also have raw TCP
ports (a database, SSH, RDP, a Minecraft server…), added from its page in
the dashboard. Each one gets a public port from the range, kept for as long
as it exists, and an allow list: only those addresses (by default, yours)
can connect, unless you open it to anyone. Ports are never created on
connect, so they are protected before they are reachable.

A port is forwarded by name, as `<port>.<subdomain>` with port 0; OpenSSH
prints the public port it got. HTTP and TCP forwards can share a connection:

```bash
ssh -p 2222 -R myapp:80:localhost:3000 -R db.myapp:0:localhost:5432 gate.example.com
# Allocated port 30042 for remote forward to localhost:5432
# → tcp://gate.example.com:30042 reaches your localhost:5432
```

The public port works too, with or without the subdomain
(`-R myapp:30042:localhost:5432`, `-R 30042:localhost:5432`).
`-R myapp:0:…` stays an HTTP tunnel. The subdomain's keys open all its
ports, and removing a key, disabling its owner or deleting the port closes
it at once.

### UDP ports and the intergate client

SSH only carries TCP, so UDP ports (a Minecraft Bedrock or Valheim server,
WireGuard, DNS…) go through the intergate client, the same binary as the
server. The dashboard serves a script that downloads the client of its
release, checks it against the release's `SHA256SUMS`, runs it and deletes
it when it ends:

```bash
curl -fsSL https://gate.example.com/tunnel.sh | sh -s -- myapp --udp mc=19132
curl -fsSL https://gate.example.com/tunnel.sh | sh -s -- --cache myapp \
  --http 3000 --tcp db=5432 --udp mc=19132     # everything, client kept in ~/.cache
intergate tunnel --server gate.example.com:2222 myapp --udp mc=19132   # installed
```

It signs in with ssh-agent or `~/.ssh` keys (`-i` for another), checks the
server's host key (written into the script, or `--host-key`, or
`~/.ssh/known_hosts`) and reconnects when the connection drops.

On Windows, `tunnel.ps1` does the same in PowerShell (5.1 or later), with the
release's `intergate-windows-amd64.zip` or `-arm64.zip`; keys come from the
OpenSSH Authentication Agent (`ssh-add`) or `%USERPROFILE%\.ssh`, and
`--cache` keeps the client in `%LOCALAPPDATA%\intergate`:

```powershell
& ([scriptblock]::Create((irm https://gate.example.com/tunnel.ps1))) myapp --udp mc=19132
```

The dashboard shows both commands, ready to copy, for a subdomain's ports.

### The desktop app

The Windows release zips also hold `intergate-gui.exe`, the client with a
window and a tray icon. Give it your dashboard's address and it looks up the
SSH endpoint and host key (`/client.json`); then the subdomain, an optional
key file, and what to forward (the HTTP tunnel and ports, by name). It shows
each forward's state and public address and a log, connects and disconnects
from the tray, can start with Windows (minimized to the tray, from the
user's `Run` key) and connect on start. Its settings live in
`%APPDATA%\intergate\app.json`. The window is WebView2, which Windows 10 and
11 have; without it the app opens in the browser. On Linux the same program
runs with its window in the browser and no tray
(`go build ./cmd/intergate-gui`).

Each remote address gets a stream of its own to your service, closed after
two minutes of silence. UDP over a TCP connection suffers head-of-line
blocking: fine for DNS, MQTT-SN or a quiet game server, jittery for
fast-paced games or calls. Source addresses can be spoofed over UDP, so
allow lists protect less than for TCP, and intergate caps what a port sends
back to an address at ten times what it received (plus 64 KiB), so it
can't be used to amplify attacks.

## Getting started

You need a domain where both `gate.example.com` and `*.gate.example.com`
point to the server. Then, on Linux or macOS:

```sh
curl -fsSL https://jgermade.github.io/intergate/setup.sh | sh
```

Without curl, `wget -qO- https://jgermade.github.io/intergate/setup.sh | sh`
does the same: the installer then downloads with wget too.

The installer downloads the release for your machine, checks it against the
release's `SHA256SUMS`, runs it once before it replaces anything, opens the
setup wizard and, on Linux with systemd, installs the service. The wizard can
leave email delivery and the owner to the dashboard: the service then prints
a one-time link to [the dashboard's setup](#the-dashboards-setup). Run the
installer again to update (the service is restarted), reconfigure, get a new
setup link or uninstall:

```sh
curl -fsSL https://jgermade.github.io/intergate/setup.sh | sh -s -- reinstall
curl -fsSL https://jgermade.github.io/intergate/setup.sh | sh -s -- configure
curl -fsSL https://jgermade.github.io/intergate/setup.sh | sh -s -- setup-url
curl -fsSL https://jgermade.github.io/intergate/setup.sh | sh -s -- uninstall --purge
```

Every release archive, the Docker image and the Helm chart also carry a
build provenance attestation signed by GitHub: it proves they were built by
this repository's release workflow, from the tagged commit. With the
[GitHub CLI](https://cli.github.com/):

```sh
gh attestation verify intergate-linux-amd64.tar.gz --repo jgermade/intergate
gh attestation verify oci://ghcr.io/jgermade/intergate:latest --repo jgermade/intergate
```

| Option | |
| --- | --- |
| `--dir DIR` | Where the binary goes. Default `/usr/local/bin`, or `INTERGATE_INSTALL_DIR`. |
| `--version TAG` | A release such as `v0.2.0`. Default the latest, or `INTERGATE_VERSION`. |
| `--config FILE` | Default `/etc/intergate/intergate.yaml`. |
| `--no-service` | Neither install nor restart the systemd service. |
| `--purge` | With `uninstall`: also delete the configuration, data and service user. |
| `-y`, `--yes` | Do not ask; `--purge` needs it when there is no terminal. |
| `INTERGATE_DOWNLOAD_URL` | A directory with `intergate-<os>-<arch>.tar.gz` and `SHA256SUMS`, used instead of GitHub. |

From source:

```bash
go build -o intergate ./cmd/intergate     # Go 1.26+
sudo ./intergate config                     # interactive setup
sudo ./intergate service --install          # run it as a systemd service
```

Then open the setup link (or, with email and administrators in the
configuration, sign in at `https://gate.example.com` with an administrator
email), register a subdomain, paste your public key (`~/.ssh/id_ed25519.pub`)
and connect with the `ssh -R` command the dashboard shows.

With Let's Encrypt, the dashboard gets a certificate on its first visit, and
each subdomain as it is registered. For [one wildcard
certificate](#wildcard-certificate-and-dns-providers) instead, set up your
DNS provider in the dashboard: **Admin → DNS**.

### The dashboard's setup

Until intergate can send sign-in codes and someone may sign in, its
dashboard shows a setup instead of anything else, in two steps:

1. **Email delivery:** the SMTP server, its encryption, user, password and
   sender. intergate signs in to the server before saving.
2. **The owner:** an email address, confirmed with a code sent to it, which
   also shows that emails arrive. The owner is then signed in, and the setup
   is gone for good.

Only the browser that opens a one-time link can do it. intergate writes one
to its log when it starts (and `intergate service --install` and
`intergate start --detached` print it), and `intergate setup-url` prints a
new one, which replaces the one before and ends a setup in progress: the
way back in when a link was used, expired or seen by someone else. A setup
session ends after an hour without use; what it saved stays.

What the setup saves lives in the database, not the configuration file,
which stays read-only (a ConfigMap in Kubernetes). The SMTP password is
encrypted (AES-256-GCM, with a key derived from the data directory's
`secret.key`) and never shown again. `intergate config` can instead read it
from an environment variable or a file, checking it with the SMTP server
first: a secrets manager such as Vault can then provide it (Vault Agent
writes files, the External Secrets Operator fills Kubernetes Secrets), and a
file is read for every email, so a renewed secret applies at once. With
`auth.email` and `auth.admins` in the configuration file there is no setup,
and the file wins over what a setup saved.

Later, owners change email delivery in the Admin page's **SMTP relay** tab
(admins see it, read-only). intergate signs in to the new relay and sends a
code through it to the owner making the change; the new relay is saved only
once they enter that code, so a relay that can't deliver never replaces one
that can. Code emails come as plain text and HTML, with the code leading the
subject and standing alone in the message, the way Gmail's "Copy code" and
Apple's AutoFill find it.

### Wildcard certificate and DNS providers

Out of the box, intergate gets a Let's Encrypt certificate for the dashboard
on its first visit, and for each subdomain as it is registered (HTTP-01 or
TLS-ALPN-01; a failure is tried again on the first visit): nothing to set
up, but every name lands in the public Certificate Transparency logs, and
Let's Encrypt allows 50 new certificates a week per domain.

With a DNS provider, intergate gets **one certificate for `gate.example.com`
and `*.gate.example.com`** instead, through ACME's DNS-01 challenge: it adds
the challenge's TXT records with the provider's API, waits until the zone's
nameservers serve them, and removes them once Let's Encrypt has checked.
New subdomains then work at once. The certificate is renewed with a third
of its life left (30 days for Let's Encrypt's 90-day certificates); a
failed try is tried again after 5, 10, 20 and 40 minutes, then hourly.
Until the wildcard certificate is there, and after a provider is removed,
the certificates of each host keep working.

Owners set it up on the Admin page's **DNS** tab (admins see it): choose the
provider, enter its credentials and, optionally, let intergate point
`*.gate.example.com` at `gate.example.com` with a CNAME (replacing the A,
AAAA or CNAME records that name had). Before saving, intergate adds a TXT
record (`_intergate-check.gate.example.com`) through the provider and
removes it, so credentials that can't change the zone are never saved. The
secrets are encrypted in the database (AES-256-GCM, with a key derived from
the data directory's `secret.key`) and never shown again. The tab shows the
certificate, its renewal, and what the last try did or why it failed, with
**Try again now**; `intergate status` shows it too.

| Provider | `provider` | Credentials |
| --- | --- | --- |
| Cloudflare | `cloudflare` | An API token with **Zone → DNS → Edit** (and **Zone → Zone → Read**, unless you give `zone_id`). |
| Google Cloud DNS | `gcp` | A service account with **DNS Administrator** (`roles/dns.admin`): its JSON key, or Application Default Credentials (`GOOGLE_APPLICATION_CREDENTIALS`, a GCE VM's, GKE Workload Identity, Cloud Run). `project` and `managed_zone` are found when left out. |
| Amazon Route 53 | `route53` | An access key allowed `route53:ListHostedZonesByName`, `ListResourceRecordSets` and `ChangeResourceRecordSets`; without one, `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`, then the EC2 instance's role. |
| DigitalOcean | `digitalocean` | A personal access token with the `domain` scopes. |
| Anything else | `exec` | A program of yours (configuration file only). |

The zone is found from the domain (the provider's zone for
`gate.example.com` or `example.com`), unless its ID is given. The DNS tab
is there when intergate gets its certificates from Let's Encrypt
(`http.tls.acme`): with your own wildcard certificate, or a reverse proxy in
front, there is nothing for it to do. So:

- **Binary and systemd service:** all of it. Secrets the configuration file
  refers to as `${VAR}` go in `/etc/intergate/intergate.env`. The service's
  sandbox hides home directories: for Google Cloud, upload the key in the
  dashboard, point `GOOGLE_APPLICATION_CREDENTIALS` at a file the
  `intergate` user can read, or use the VM's service account.
- **Docker:** all of it, with the certificate kept in the `/data` volume.
  The image has no shell, so an `exec` provider must be a program that runs
  on its own (a static binary in `/data`), not a script; intergate says so
  when it starts.
- **Kubernetes (Helm):** with `traefik.tls.passthrough`, all of it:
  Traefik passes TLS through to intergate. In the chart's default mode,
  Traefik terminates TLS, so the wildcard certificate comes from Traefik's
  DNS-01 resolver or cert-manager, set up as you install, and the DNS tab
  does not show. See [Kubernetes with Traefik](#kubernetes-with-traefik).

The configuration file can set the provider instead, and then wins over the
dashboard, which shows it read-only:

```yaml
dns:
  provider: cloudflare
  cloudflare:
    api_token: ${CLOUDFLARE_API_TOKEN}
  wildcard_record: true   # optional: *.gate.example.com CNAME gate.example.com
```

Only the configuration file can run a program or name a file on the server:
the `exec` provider, and `gcp`'s `credentials_file` (the dashboard takes the
key's content). `exec` covers any other DNS service — RFC 2136 with
`nsupdate`, a registrar's API, an `acme.sh` hook… — as
`PROGRAM set NAME TYPE TTL VALUE...` (replace those records) and
`PROGRAM delete NAME TYPE`, with fully qualified names without the final
dot and TXT values unquoted, in intergate's environment, exiting 0 once
done. For instance, with `nsupdate` and a TSIG key:

```sh
#!/bin/sh
# /etc/intergate/dns-hook.sh: dns.exec.command
action=$1 name=$2 type=$3 ttl=$4
{
  echo "server ns1.example.com"
  echo "update delete $name. $type"
  if [ "$action" = set ]; then
    shift 4
    for v in "$@"; do
      case $type in TXT) v="\"$v\"" ;; CNAME) v="$v." ;; esac
      echo "update add $name. $ttl $type $v"
    done
  fi
  echo send
} | nsupdate -k /etc/intergate/tsig.key
```

intergate waits up to `dns.propagation_timeout` (2 minutes) for
every authoritative nameserver of the zone to serve the challenge's
records; `dns.nameservers` asks others instead, e.g. with split-horizon DNS
or when outgoing DNS is only allowed to some servers.

### Commands

| Command | |
|---|---|
| `intergate config` | Interactive wizard. Creates the configuration on first run; then manages subdomains, SSH keys, users, server settings and where the SMTP password of the dashboard's setup comes from. `--accessible` uses plain prompts (also for screen readers and scripts: it accepts piped answers). |
| `intergate setup-url` | Print a new one-time link to [the dashboard's setup](#the-dashboards-setup), replacing the one before. Only the URL goes to stdout. |
| `intergate start` | Run in the foreground. `--detached` runs in the background, logging to `<data_dir>/intergate.log`. |
| `intergate stop` / `status` | Stop a detached server / show whether it runs, with live counters. |
| `intergate service --install` | Install a hardened systemd service: binary in `/usr/local/bin`, a dedicated `intergate` user owning the data directory, `CAP_NET_BIND_SERVICE` for ports 80/443. `--uninstall` and `--status` too; `--dry-run` shows what would happen. |

Every command takes `--config FILE`; otherwise `$INTERGATE_CONFIG`,
`./intergate.yaml` or `/etc/intergate/intergate.yaml` is used.

`intergate config` and `status` talk to the running server through a Unix
socket in the data directory (mode 0600: root or the service user), so changes
apply to live tunnels immediately.

## Deployment

### Binary and systemd

As above: `intergate config`, then `intergate service --install`. Secrets
can stay out of the configuration file: write `${SMTP_PASSWORD}` and put
`SMTP_PASSWORD=...` in `/etc/intergate/intergate.env`, which systemd reads
as root. That file also serves the SMTP password of the dashboard's setup,
once `intergate config` reads it from the environment.

### Docker

The image keeps the configuration and all state in `/data`:

```bash
docker volume create intergate
docker run -it --rm -v intergate:/data ghcr.io/jgermade/intergate config
docker run -d --name intergate --restart unless-stopped -v intergate:/data \
  -p 80:80 -p 443:443 -p 2222:2222 ghcr.io/jgermade/intergate
# with tcp.ports: 30000-30019, publish the range as well, TCP and UDP:
#   -p 30000-30019:30000-30019 -p 30000-30019:30000-30019/udp
docker exec intergate intergate setup-url       # the link to the dashboard's setup
docker exec -it intergate intergate config     # manage subdomains, keys and users
```

Every release publishes the image to `ghcr.io/jgermade/intergate`; before
the first one, build it with `docker build -t intergate .`. See
[`deploy/docker/compose.yaml`](deploy/docker/compose.yaml) for Compose.
With Docker alone, choose Let's Encrypt in the setup: intergate gets a
certificate for each registered subdomain on demand, so no DNS challenge is
needed — or set up your DNS provider in the dashboard (Admin → DNS) for one
wildcard certificate.

### Kubernetes with Traefik

[`deploy/helm/intergate`](deploy/helm/intergate) installs intergate behind
Traefik v3. Every release publishes it to `oci://ghcr.io/jgermade/charts`
and to the classic repository `https://jgermade.github.io/intergate/charts`
(for tools without OCI support, such as helm-dashboard), so there is nothing
to clone (from a clone, `deploy/helm/intergate` works the same):

- an `IngressRoute` for `gate.example.com` and its subdomains, with TLS
  from Traefik or from intergate itself (see below);
- an `IngressRouteTCP` on a dedicated Traefik entry point for SSH, with the
  PROXY protocol so intergate sees client addresses — or a `LoadBalancer`
  Service instead;
- with `tcp.enabled`, a `LoadBalancer` Service for the ports (`tcp.first`
  to `tcp.last`, TCP and, with `tcp.udp`, UDP), with
  `externalTrafficPolicy: Local` so allow lists see client addresses. Keep
  the range small: it is one or two Service ports each.

Who terminates TLS is the choice to make:

- **Traefik** (the default): it needs a certificate for `gate.example.com`
  and `*.gate.example.com` from the start — a Traefik resolver with a
  DNS-01 challenge (`traefik.tls.certResolver`), an existing wildcard
  secret (`traefik.tls.secretName`) or cert-manager (`certManager`) — with
  the DNS provider's credentials in Traefik's or cert-manager's
  configuration. Traefik's HTTP middlewares and access logs apply, and
  intergate reads client addresses from `X-Forwarded-For`.
- **intergate** (`traefik.tls.passthrough: true`): Traefik routes the HTTPS
  connections of the domain and its subdomains by name without decrypting
  them, with the PROXY protocol so intergate sees client addresses (and
  trusts no `X-Forwarded-For`). intergate then gets its certificates from
  Let's Encrypt as the binary does: the dashboard works once installed,
  each subdomain gets one as it is registered, and an owner can set up a
  DNS provider in the dashboard (Admin → DNS) for [one wildcard
  certificate](#wildcard-certificate-and-dns-providers). Traefik's HTTP
  middlewares don't apply to these hosts, and the certificates live on the
  volume, so keep `persistence` enabled. Plain HTTP goes through the
  `traefik.tls.httpEntryPoints` (`web`) to intergate, which redirects it
  and answers HTTP-01 challenges.

```bash
helm install intergate oci://ghcr.io/jgermade/charts/intergate \
  --set domain=gate.example.com \
  --set traefik.tls.certResolver=letsencrypt-dns
# or, with intergate getting its own certificates:
helm install intergate oci://ghcr.io/jgermade/charts/intergate \
  --set domain=gate.example.com \
  --set traefik.tls.passthrough=true --set traefik.tls.acmeEmail=you@example.com
kubectl exec deploy/intergate -- intergate setup-url    # the link to the dashboard's setup
kubectl exec -it deploy/intergate -- intergate config
```

The setup saves email delivery and the owner on the volume, so the release's
values need neither. To manage them with Helm instead, set
`config.auth.admins` and `config.auth.email` in the values, with the SMTP
password as `${SMTP_PASSWORD}` in `secretEnv` or `existingSecret`; then
there is no setup. `existingSecret` is also where a password the setup saved
can move to, from Vault through the External Secrets Operator: put it in the
Secret, then choose the environment variable in `intergate config`.

Or from the classic repository:

```bash
helm repo add intergate https://jgermade.github.io/intergate/charts
helm install intergate intergate/intergate --set domain=gate.example.com ...
```

Traefik needs a TCP entry point for SSH, e.g. in the Traefik chart's values:

```yaml
ports:
  ssh:
    port: 2222
    expose: {default: true}
    exposedPort: 2222
    protocol: TCP
```

intergate runs as a single replica: tunnels live in the memory of the
process that holds the SSH connections.

### Upgrading from gate2net or gate2sky

intergate was called gate2net, and gate2sky before. Their configurations and
databases keep working: without a configuration under the new name,
intergate reads `$GATE2NET_CONFIG`, `./gate2net.yaml` or
`/etc/gate2net/gate2net.yaml` (and, in Docker, `/data/gate2net.yaml`), then
the same under gate2sky, and renames `gate2net.db` (or `gate2sky.db`) in the
data directory to `intergate.db`. Everyone signs in again once: the cookies
have new names. The desktop app keeps its settings; switching its start with
the system off or on removes gate2net's entry. To move a systemd install to
the new names:

```bash
old=gate2net   # or gate2sky
sudo systemctl disable --now $old
sudo mv /etc/$old /etc/intergate
sudo mv /etc/intergate/$old.yaml /etc/intergate/intergate.yaml
sudo mv /etc/intergate/$old.env /etc/intergate/intergate.env 2>/dev/null
sudo mv /var/lib/$old /var/lib/intergate
sudo sed -i "s#/var/lib/$old#/var/lib/intergate#g" /etc/intergate/intergate.yaml
curl -fsSL https://jgermade.github.io/intergate/setup.sh | sh   # installs intergate and its service
sudo rm /etc/systemd/system/$old.service /usr/local/bin/$old
sudo systemctl daemon-reload && sudo userdel $old
```

With Docker, use the `ghcr.io/jgermade/intergate` image on the same volume.
With Compose, the volume is now `intergate`: keep the old one by its name
(`docker volume ls`), e.g. `intergate: {external: true, name: docker_gate2net}`
under `volumes:`. With Helm, upgrade the release to the `intergate` chart
with your values and `--set nameOverride=gate2net` (or `gate2sky`): it keeps
the old names for its resources, so it keeps its volume.

```bash
helm upgrade gate2net oci://ghcr.io/jgermade/charts/intergate -f my-values.yaml --set nameOverride=gate2net
```

## Configuration

See [`intergate.example.yaml`](intergate.example.yaml) for every option.
Highlights:

- `public_url`: the dashboard URL. Tunnels live on its subdomains.
- `http.tls`: Let's Encrypt (`acme`) or a wildcard certificate
  (`cert_file`/`key_file`). Leave it out behind a TLS-terminating proxy and
  set `http.trust_proxy_headers`.
- `auth.email`: SMTP settings for sign-in codes (`log_only: true` writes them
  to the log for local development). Without it, [the dashboard's
  setup](#the-dashboards-setup) asks for them.
- `auth.providers`: optional `github` or `oidc` providers (Google, GitLab,
  Microsoft Entra ID, Keycloak, Authentik...). Their callback URL is
  `<public_url>/auth/<id>/callback`.
- `auth.admins`, `auth.allowed_emails`, `auth.allowed_domains`,
  `auth.allow_everyone`: who may sign in. Users an administrator adds from
  the dashboard or `intergate config` may sign in too. On the dashboard's
  Admin page each user is an owner, an admin or a user: admins manage every
  subdomain and account but owners', owners manage everything, and
  `auth.admins` are always owners. With none of them, the dashboard's setup
  asks for the owner.
- `ssh.proxy_protocol`, `http.tls.proxy_protocol`: expect a PROXY protocol
  header from a load balancer, or from a proxy that passes TLS through.
  Only when that proxy is the only way to the port: a header tells
  intergate the client's address.
- `dns`: a DNS provider for [one wildcard
  certificate](#wildcard-certificate-and-dns-providers), with
  `http.tls.acme`. Without it, owners can set one up from the dashboard.
- `tcp.ports`: the range TCP and UDP ports are allocated from (e.g. `30000-30019`);
  `tcp.max_ports` per subdomain (5), `tcp.public_host` for their addresses
  (the SSH host by default) and `tcp.listen_host` to listen on one interface.

For local development, `*.localhost` resolves to 127.0.0.1 in browsers:

```yaml
public_url: http://localhost:8080
auth:
  admins: [you@example.com]
  email: {log_only: true}
```

## Security notes

- **SSH:** public-key authentication only; the key is checked again for every
  forward, so revoking it takes effect immediately. Local forwarding
  (`ssh -L`) and other channel types are refused.
- **Accounts** are identified by verified email. Email codes are 6 digits,
  single use, valid 10 minutes, bound to the browser that asked for them,
  burned after 5 wrong guesses and rate limited per address and IP. The
  response is the same whether or not an address may sign in, and no email is
  sent to addresses that may not.
- **Setup:** while intergate has no email delivery or nobody may sign in,
  only the browser that redeemed the one-time link (24 random bytes, only a
  hash kept in memory) can set it up; the link is spent when the setup
  starts, not when the page loads, so link previews can't burn it. Its
  session is a host-only `HttpOnly` cookie that ends after an hour without
  use or with a new link. The owner proves their address with a code.
- **SMTP relay changes** from the Admin page are for owners only, and save
  only after the owner enters a code the new relay delivered to their
  address (6 digits, single use, 10 minutes, 5 tries, kept in memory).
- **SMTP password** saved by the setup: AES-256-GCM with a key derived
  (HKDF-SHA256) from the data directory's `secret.key`, so the database alone
  (a backup, a copy) does not give it away; whoever has the whole data
  directory has it, as they have the SSH host key. Never sent back to the
  browser or the admin socket. It can come from an environment variable or
  a file instead (`intergate config`).
- **Passkeys** require user verification. Tunnel subdomains may claim the same
  WebAuthn RP ID as the dashboard, so assertions are only accepted from the
  dashboard's exact origin; challenges are single use.
- **Dashboard:** server-side sessions (only a hash of the token is stored),
  `__Host-` cookies over HTTPS, CSRF tokens plus an `Origin` check on every
  state change (tunnels are same-site with the dashboard, so SameSite cookies
  alone are not enough), and a strict Content-Security-Policy: scripts only
  from the dashboard itself or with the page's per-response nonce, never
  `eval`, no inline styles, no connections to other hosts.
- **Protected tunnels:** the dashboard issues a short-lived, single-use,
  host-bound token that the tunnel host exchanges for a host-only, HttpOnly
  cookie tied to the dashboard session. Signing out revokes access to every
  tunnel. intergate's cookies are stripped before requests reach the app.
  Signed-in users who may not open a tunnel see it as offline.
- **DNS providers:** their credentials can change your zone, so give them
  as little as the provider allows (Cloudflare: **Zone → DNS → Edit** on
  that zone only). Set from the dashboard, only owners change them, after
  intergate has made a change with them, and the secrets are encrypted like
  the SMTP password, never sent back to the browser or the admin socket.
  The dashboard can't set what runs a program or reads a file on the
  server (`exec`, `credentials_file`): a stolen owner session can't turn
  into code execution.
- **TCP ports** check every connection's address against the port's allow
  list, which needs the real client address: publish the range directly, or
  keep it (`externalTrafficPolicy: Local`) behind a load balancer. Data is
  not encrypted by intergate between the visitor and the server: use the
  service's own TLS (PostgreSQL, MySQL and SSH have it).
- **OAuth:** authorization code flow with PKCE, state and (OIDC) nonce checks.

## Development

```bash
go test -race ./...
```

`scripts/setup-check.sh` walks the installer against builds of this tree:
install, update, reinstall, a bad checksum, uninstall and `--purge`.

The dashboard is a [jq79](https://github.com/jgermade/jq79) app in
[`internal/web/ui`](internal/web/ui): single-file `.html` components loaded
at runtime, with no build step, embedded in the binary and talking to a JSON
API under `/api`. The server sends one page shell for every dashboard path,
with a fresh CSP nonce and the session's boot data; jq79 builds each
component's functions as scripts carrying that nonce
(`Component79.safeEval({ nonce: true })`). Edit a component and rebuild the
binary to see it.

It draws with a design system in
[`internal/web/ui/theme/default`](internal/web/ui/theme/default):
`tokens.css` holds every value (colours by role in two tones, type, space,
radii, shadows, motion), `icons.js` the icons, and `components/` the
building blocks — `Button`, `Modal`, `Tabs`, `Card`, `Badge`, `Alert`,
`Facts`, `Switch`, `Segmented`, `ChoiceCards`, `Icon` — which draw with those
tokens alone. `app.css` declares no colour of its own. Every component, in
both tones, is on one page at `/ui/theme/default/` of any running
dashboard, and at
[jgermade.github.io/intergate/theme](https://jgermade.github.io/intergate/theme/)
as of the latest release; **Inspect** beside each shows a parent component
that uses it, and its own code, editable, with a live preview and a button
that copies the change as a patch for `git apply`.
[`scripts/theme-site.sh`](scripts/theme-site.sh) builds that static copy:
`scripts/theme-site.sh /tmp/theme`, then serve the folder.

`internal/e2e` runs the whole system: SSH clients opening tunnels, browsers
signing in with email codes, a software WebAuthn authenticator and a fake
OpenID Connect provider, and the configuration wizard against a live admin
socket.

### Builds and releases

Two workflows:

- **Build** (`.github/workflows/build.yml`) runs on every push: downloads
  and verifies the dependencies, runs the tests, builds
  `intergate-<os>-<arch>.tar.gz` for Linux and macOS (amd64, arm64), walks
  the installer against this tree, builds the Docker image, renders the Helm
  chart, checks the landing and assembles the design system's demo.
- **Release** (`.github/workflows/release.yml`) is started by hand from the
  Actions tab on the default branch, choosing `patch`, `minor` or `major`. It
  raises [`VERSION`](VERSION) and the Helm chart's version, commits and tags
  `vX.Y.Z`, runs Build on that commit, creates the GitHub release with the
  binaries, `SHA256SUMS` (what `setup.sh` installs) and the Helm chart, pushes
  the Docker image and the chart to GHCR, attests the provenance of all of
  them, and deploys [`pages/`](pages/) — the landing and `setup.sh` — to
  GitHub Pages, with the design system's demo under `theme/` and the Helm
  repository's `charts/index.yaml`, which adds each release's chart to the
  one already served. `dry-run` builds everything
  and publishes nothing.

The landing is built from [`scripts/landing`](scripts/landing): edit
`template.html` (or the drawings in `hero.py`, whose geometry is computed),
then run `python3 scripts/landing/gen.py scripts/landing/template.html
pages/index.html`. Build checks that the two agree. The icon is
[`pages/favicon.svg`](pages/favicon.svg), the same file as the dashboard's
[`internal/web/ui/favicon.svg`](internal/web/ui/favicon.svg) (the landing's
header inlines it); after changing it, copy it to both and run
`node scripts/landing/icons.js`, which renders `favicon.ico` (also the
desktop app's tray icon) and `apple-touch-icon.png`, on a dark tile because
iOS fills transparency with black, from it and writes
[`logo-mark.svg`](internal/web/ui/logo-mark.svg) for the dashboard's header
and sign-in page. Link previews show
[`pages/og.png`](pages/og.png), the hero at 1200×630: after changing the
hero, regenerate the landing, then run `node scripts/landing/og.js`.

## Roadmap

- Sharing private subdomains with specific users.
- Custom domains (CNAME to a subdomain).
- Request inspector in the dashboard.
