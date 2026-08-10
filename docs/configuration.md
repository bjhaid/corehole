# Configuration Reference

corehole reads YAML configuration from the path passed to
`corehole serve --config`. If the file does not exist, corehole starts with the
built-in defaults from `internal/config/config.go`.

YAML is decoded over those defaults. Omitting a section keeps its default values,
but replacing a list, such as `dns.resolvers`, replaces the default list.

The YAML/default config bootstraps the SQLite `app_config` row only when that
row does not exist. After `app_config` exists, the persisted config is the active
config for startup. YAML is still read first so corehole can find
`storage.path`, but later YAML changes, including `blocking.blocklists`, are not
applied automatically to the active config. Startup logs report the active
config source and active blocklist count.

## Supported Fields

| Path | Type | Default | Allowed values | Behavior |
| --- | --- | --- | --- | --- |
| `dns.listen` | string | `":53"` | Any non-empty listen-style string accepted by the generated CoreDNS server block, such as `":53"`, `":1053"`, or `"1053"` | Selects the DNS service port. corehole starts both UDP and TCP DNS service. YAML overrides the built-in default. The current CoreDNS generation uses only the port; a host in values like `"127.0.0.1:1053"` is discarded and CoreDNS receives `.:1053`. Binding port 53 usually requires root/admin privileges or a service manager capability such as `CAP_NET_BIND_SERVICE`; use `":1053"` for unprivileged local development. |
| `dns.resolvers` | list of resolver objects | one enabled Cloudflare resolver | List may be omitted, but at least one resolver must be enabled after defaults and YAML are applied | Enabled resolvers are passed to the CoreDNS `forward .` plugin by address. Disabled resolvers are ignored. |
| `dns.resolvers[].name` | string | `"cloudflare"` on the built-in default resolver; `""` for resolver objects you add without a name | No validation | Human-readable resolver name. It is logged and shown in admin snapshots. It does not affect forwarding. |
| `dns.resolvers[].address` | string | `"1.1.1.1:53"` on the built-in default resolver; `""` for resolver objects you add without an address | Required for enabled resolvers; must not contain whitespace or braces | Upstream address passed to CoreDNS `forward .`. Plain DNS examples: `"1.1.1.1:53"` or `"9.9.9.9:53"`. DoT and DoH may also be expressed with `protocol` or with CoreDNS target prefixes such as `"tls://9.9.9.9:853"` or `"https://1.1.1.1"`. |
| `dns.resolvers[].protocol` | string | `"udp"` on the built-in default resolver; `""` for resolver objects you add without a protocol | `""`, `"udp"`, `"dns"`, `"tcp"`, `"tls"`, or `"https"` for enabled resolvers | Controls generated CoreDNS forwarding where practical. `udp`, `dns`, or empty uses normal CoreDNS DNS forwarding. `tls` emits `tls://` when the address has no scheme. `https` emits `https://` when the address has no scheme. `tcp` emits a `force_tcp` forwarding block; because CoreDNS applies `force_tcp` to the whole `forward` stanza, enabled `tcp` resolvers cannot be mixed with enabled non-TCP resolvers. |
| `dns.resolvers[].tls_server_name` | string | `""` | Must not contain whitespace or braces | Used with `protocol: tls` to emit CoreDNS per-upstream TLS server name syntax, for example `tls://9.9.9.9%dns.quad9.net:853`. This value is now included in admin config snapshots when present. |
| `dns.resolvers[].enabled` | boolean | `true` on the built-in default resolver; `false` for resolver objects you add without `enabled` in YAML | `true` or `false` | Only enabled resolvers are used. YAML resolver objects should set `enabled: true` unless the resolver is intentionally disabled. |
| `dns.cache_ttl` | integer seconds | `30` | `0` or greater | Caps CoreDNS cache duration for DNS responses. `0` omits the CoreDNS `cache` directive and disables corehole's generated DNS cache. Positive values emit a CoreDNS `cache` block. |
| `dns.cache_success_capacity` | integer entries | `32768` | `1024` or greater when `dns.cache_ttl` is positive | Capacity for cached successful responses. CoreDNS divides capacity across 256 shards and rounds configured capacity down to a multiple of 256. |
| `dns.cache_denial_capacity` | integer entries | `4096` | `1024` or greater when `dns.cache_ttl` is positive | Capacity for cached denial/failure responses such as NXDOMAIN/NODATA. This is intentionally lower than successful-response capacity by default. CoreDNS does not cache generic error responses. |
| `dns.dnssec.enabled` | boolean | `false` | `true` or `false` | Enables DNSSEC upstream assistance when paired with `mode: upstream`. When disabled, use `mode: off`. |
| `dns.dnssec.mode` | string | `"off"` | `"off"`, `"upstream"`, or empty when `enabled: true` | `off` disables DNSSEC assistance. `upstream` sends DNSSEC request flags upstream and preserves validated upstream AD status for clients that request it. Empty mode with `enabled: true` is treated as `upstream`. `local` is not implemented and is rejected. |
| `dns.conditional_forwarding.enabled` | boolean | `false` | `true` or `false` | Enables one local-domain/reverse-zone conditional forwarding rule before the default `forward .` rule. |
| `dns.conditional_forwarding.domain` | string | `""` | Required when conditional forwarding is enabled; must not contain whitespace or braces | Domain or reverse zone to forward, such as `"lan"` or `"168.192.in-addr.arpa"`. |
| `dns.conditional_forwarding.resolver` | string | `""` | Required when conditional forwarding is enabled; must not contain whitespace or braces | Upstream resolver for the conditional domain, such as `"192.168.1.1:53"`. |
| `dns.conditional_forwarding.protocol` | string | `""` | `""`, `"udp"`, `"dns"`, `"tcp"`, `"tls"`, or `"https"` | Uses the same CoreDNS target behavior as upstream resolver `protocol`. |
| `dns.conditional_forwarding.tls_server_name` | string | `""` | Must not contain whitespace or braces | Optional TLS server name for a TLS conditional forwarding resolver. |
| `admin.listen` | string | `"127.0.0.1:8080"` | Any non-empty TCP listen address accepted by Go `net.Listen`, such as `"127.0.0.1:8080"` or `"0.0.0.0:8080"` | Address for the admin console and admin API. Unlike `dns.listen`, the host is honored. |
| `storage.path` | string | `"corehole.db"` | Any non-empty SQLite database path | SQLite database path. The parent directory is created if needed. The database stores audit events, all-time audit action counters, admin users, and persisted app config. |
| `blocking.response` | string | `"nxdomain"` | `"nxdomain"`, `"null-ip"`, or `"refused"` | DNS response mode for blocked queries. `nxdomain` returns NXDOMAIN. `null-ip` returns `0.0.0.0` for A queries and `::` for AAAA queries, and NXDOMAIN for other query types. `refused` returns REFUSED. |
| `blocking.bundled` | boolean | `true` | `true` or `false` | Enables or disables the embedded seed blocklist from `internal/blocklist/seed.txt`. When enabled, bundled entries are combined with entries loaded from `blocking.blocklists`. |
| `blocking.paused` | boolean | `false` | `true` or `false` | Starts DNS filtering in a paused state when the persisted config is active. Paused blocking allows queries that would otherwise match deny rules. Prefer the Blocklists page in the admin console for day-to-day pause/resume changes because it updates the running DNS runtime immediately. |
| `blocking.pause_until` | string | `""` | Empty or RFC3339 timestamp | Optional end time for a timed pause. Empty with `blocking.paused: true` means pause indefinitely. Expired timestamps are ignored by the DNS runtime. |
| `blocking.blocklists` | list of strings | empty list | Local file paths | Files to open and parse at startup. Entries from these files decide which queries are blocked in addition to any bundled entries. Missing or unreadable files fail startup. |

Unknown YAML fields are not rejected by the current loader. Treat a typo as
ignored unless validation fails for another reason.

## Operational Caveats

The `corehole serve` command loads YAML once at startup. Changing the YAML file
does not affect a running process. If the configured SQLite database already has
an `app_config` row, changing YAML also does not affect the next process start
until the persisted config is updated or removed.

Audit retention cleanup removes old detailed `audit_events` rows only. The
all-time audit action counters used by dashboard totals are retained across
cleanup and restarts; they can be rebuilt from remaining `audit_events` rows if
an operator intentionally needs to reset them.

Fields read at startup by the running application:

- `dns.listen`: used to build the CoreDNS server; restart required after YAML changes.
- `dns.resolvers`: enabled resolver addresses are used to build the CoreDNS
  `forward .` line; restart required after YAML changes.
- `dns.cache_ttl`: used to build the CoreDNS `cache` directive; restart
  required after YAML changes.
- `dns.cache_success_capacity` and `dns.cache_denial_capacity`: used inside the
  generated CoreDNS `cache` block; restart required after YAML changes.
- `dns.dnssec`: used to add corehole's upstream DNSSEC helper before CoreDNS
  forwarding; restart required after YAML changes.
- `dns.conditional_forwarding`: used to build a conditional CoreDNS `forward`
  line before the default upstream forwarder; restart required after YAML
  changes.
- `admin.listen`: used before the admin HTTP server starts; restart required
  after YAML changes.
- `storage.path`: used to open SQLite before admin and DNS services start;
  restart required after YAML changes.
- `blocking.response`: copied into the DNS plugin runtime at startup; restart
  required after YAML changes.
- `blocking.paused` and `blocking.pause_until`: copied into the DNS plugin
  runtime at startup. Use the admin console to pause or resume blocking in the
  running process.
- `blocking.bundled`: copied into the blocklist package's bundled-default
  setting during config load; restart required after YAML changes.
- `blocking.blocklists`: files are opened and parsed at startup; restart
  required after changing the list or changing a referenced blocklist file.

The admin API supports `GET /api/config` in `corehole serve`; it returns the
persisted active configuration, active upstreams, cache TTL, DNSSEC mode, and
conditional forwarding settings. `PUT /api/config` saves the persisted
configuration used by later startups.

`PUT /api/config` can persist these JSON fields to the SQLite `app_config`
table:

- `dns.listen`
- `dns.resolvers`
- `dns.cache_ttl`
- `dns.cache_success_capacity`
- `dns.cache_denial_capacity`
- `dns.dnssec`
- `dns.conditional_forwarding`
- `admin.listen`
- `blocking.response`
- `blocking.bundled`
- `blocking.blocklists`

That update path preserves `storage.path`. DNS resolver/cache/DNSSEC and
conditional forwarding changes can apply through DNS hot reload when the DNS
listen address is unchanged and the active update manager has a DNS reloader.
If hot reload is unavailable, if the DNS listen address changes, or if a change
touches `admin.listen` or configured blocklist paths, the response reports
`restart_required: true`.

To force a later startup to seed active config from YAML again, stop corehole and
delete the persisted app config row from the selected database:

```sh
sqlite3 ./corehole.db 'DELETE FROM app_config WHERE id = 1;'
corehole serve --config ./corehole.yaml
```

## Validation Rules

Startup validation fails when:

- `dns.listen` is empty.
- `admin.listen` is empty.
- `storage.path` is empty.
- no resolver is enabled.
- an enabled resolver has an empty `address`.
- an enabled resolver uses an unsupported `protocol`.
- enabled TCP resolvers are mixed with enabled non-TCP resolvers.
- `dns.cache_ttl` is negative.
- `dns.cache_success_capacity` or `dns.cache_denial_capacity` is below `1024`
  while `dns.cache_ttl` is positive.
- `dns.dnssec.enabled` is true without `mode: upstream`.
- `dns.dnssec.mode` is `upstream` while `enabled` is false.
- `dns.dnssec.mode` is any unsupported value, including `local`.
- `dns.conditional_forwarding.enabled` is true and `domain` or `resolver` is empty.
- a CoreDNS-generated token field contains whitespace or braces.
- `blocking.response` is empty.
- `blocking.response` is not `nxdomain`, `null-ip`, or `refused`.
- `blocking.pause_until` is non-empty and not an RFC3339 timestamp.

Additional runtime errors can still happen after config validation:

- binding the default DNS listener `:53` usually requires root/admin privileges
  or a service manager capability such as `CAP_NET_BIND_SERVICE`.
- invalid listener syntax or a busy port fails DNS or admin startup.
- an invalid upstream address can cause CoreDNS startup or forwarding failures.
- DoH upstream addresses with paths are rejected by CoreDNS; use host or
  host:port only and CoreDNS uses `/dns-query`.
- missing or unreadable blocklist files fail startup.
- scanner read errors while parsing blocklist files fail startup; invalid
  blocklist entries are ignored.
- an unwritable database path or parent directory fails storage startup.

Common resolver mistake:

```yaml
dns:
  resolvers:
    - name: quad9
      address: "9.9.9.9:53"
      protocol: udp
```

In YAML, this resolver is disabled because `enabled` is omitted on a newly
provided resolver object. Add `enabled: true`.

## Unprivileged Development Example

The built-in DNS listener default is `:53`. This override keeps DNS on a
non-privileged local development port:

```yaml
dns:
  listen: ":1053"
  cache_ttl: 30
  cache_success_capacity: 32768
  cache_denial_capacity: 4096
  dnssec:
    enabled: false
    mode: off
  conditional_forwarding:
    enabled: false
    domain: ""
    resolver: ""
  resolvers:
    - name: cloudflare
      address: "1.1.1.1:53"
      protocol: udp
      enabled: true
admin:
  listen: "127.0.0.1:8080"
storage:
  path: "./corehole.db"
blocking:
  response: nxdomain
  bundled: true
  blocklists:
    - ./blocklist.txt
```

Run it with:

```sh
go run ./cmd/corehole serve --config ./corehole.yaml
```

Then query it from another shell:

```sh
dig @127.0.0.1 -p 1053 blocked.example A
```

## Production/LAN Example

This exposes the admin console on the LAN and uses the default DNS port 53.
Binding port 53 usually requires elevated privileges or a service manager with
the right capability.

```yaml
dns:
  listen: ":53"
  cache_ttl: 300
  cache_success_capacity: 65536
  cache_denial_capacity: 8192
  dnssec:
    enabled: true
    mode: upstream
  conditional_forwarding:
    enabled: true
    domain: "lan"
    resolver: "192.168.1.1:53"
  resolvers:
    - name: quad9
      address: "9.9.9.9:53"
      protocol: udp
      enabled: true
    - name: cloudflare
      address: "1.1.1.1:53"
      protocol: udp
      enabled: true
admin:
  listen: "0.0.0.0:8080"
storage:
  path: "/var/lib/corehole/corehole.db"
blocking:
  response: null-ip
  bundled: true
  blocklists:
    - "/etc/corehole/blocklists/ads.txt"
    - "/etc/corehole/blocklists/tracking.txt"
```

## DNSSEC

Default:

```yaml
dns:
  dnssec:
    enabled: false
    mode: off
```

Trusted validating upstream mode:

```yaml
dns:
  dnssec:
    enabled: true
    mode: upstream
```

`upstream` is the only enabled DNSSEC mode. It relies on the configured
upstream resolvers to do validation. corehole sends DNSSEC-capable upstream
queries and can pass DNSSEC proof records and AD status back to clients that
ask for them, but corehole does not perform local recursive validation itself.
This is upstream validation assistance, not local Pi-hole/Unbound-style
recursive validation.

`local` validation is unavailable and rejected by config validation. To get
local recursive validation, run a validating resolver such as Unbound separately
and configure corehole to forward to it, then use `mode: upstream`.

Verification guidance:

```sh
dig @127.0.0.1 -p 1053 dnssec-failed.org A
dig @127.0.0.1 -p 1053 cloudflare.com A +dnssec
dig @127.0.0.1 -p 1053 cloudflare.com A +dnssec +adflag
```

With a trusted validating upstream, intentionally broken domains such as
`dnssec-failed.org` should fail according to that upstream's policy, and
successful signed domains may include DNSSEC records/AD status when requested.
Without a validating upstream, enabling `mode: upstream` does not make corehole
validate responses locally.

## Unsupported DNS Settings

corehole does not currently implement DHCP.

## Blocklist Format

Blocklist files are local text files. Supported lines include:

```text
# comments and blank lines are ignored
blocked.example

# hosts-file style lines are supported
0.0.0.0 ads.example tracker.example
127.0.0.1 metrics.example

# suffix/wildcard entries are supported
*.bad.example
```

Rules:

- comments start at `#`.
- plain domain lines must contain exactly one domain.
- hosts-file style lines start with an IP address followed by one or more domains.
- domains are lowercased and trailing dots are removed.
- IP-address entries are ignored as block targets.
- domains with empty labels, labels longer than 63 characters, total length over
  253 characters, underscores, or leading/trailing hyphens are ignored.
- `*.example.com` creates a suffix rule for subdomains under `example.com`.
