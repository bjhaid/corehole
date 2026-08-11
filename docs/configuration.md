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
| `dns.cache_success_ttl` | integer seconds | `3600` | `0` to `3600` | Maximum CoreDNS cache TTL for successful responses. CoreDNS still respects shorter upstream record TTLs; this cap prevents successful responses from living longer than one hour. Set both success and denial TTLs to `0` to omit the generated CoreDNS `cache` block. |
| `dns.cache_denial_ttl` | integer seconds | `30` | `0` to `1800` | Maximum CoreDNS cache TTL for denial/failure responses such as NXDOMAIN/NODATA. Keep this shorter than successful responses so newly-created domains are not hidden by stale negative cache entries for long. |
| `dns.cache_ttl` | integer seconds | unset | `0` to `1800` | Deprecated compatibility field. If the split success/denial TTL fields are absent, this value is used for both success and denial cache TTLs. Prefer `cache_success_ttl` and `cache_denial_ttl`. |
| `dns.cache_success_capacity` | integer entries | `32768` | `1024` or greater when cache is enabled | Capacity for cached successful responses. CoreDNS divides capacity across 256 shards and rounds configured capacity down to a multiple of 256. |
| `dns.cache_denial_capacity` | integer entries | `4096` | `1024` or greater when cache is enabled | Capacity for cached denial/failure responses. This is intentionally lower than successful-response capacity by default. CoreDNS does not cache generic error responses. |
| `dns.cache_prefetch_amount` | integer hits | `5` | `0` or greater | Enables CoreDNS cache prefetch for popular entries once this many queries are seen without gaps longer than `cache_prefetch_duration`. Set to `0` to disable prefetch. |
| `dns.cache_prefetch_duration` | integer seconds | `60` | `0` or greater | Popularity window for CoreDNS cache prefetch. |
| `dns.cache_prefetch_percent` | integer percent | `10` | `0` to `100` | Remaining-TTL threshold that triggers CoreDNS prefetch for popular entries. |
| `dns.rewrites` | list of rewrite rule objects | empty list | Valid rewrite rules | CoreDNS `rewrite` rules managed from the Custom DNS page. Corehole currently exposes name, type, TTL, and RCODE rewrites. EDNS0 and CNAME rewrites are intentionally not exposed yet. |
| `dns.rewrites[].enabled` | boolean | `false` for newly-created YAML objects | `true` or `false` | Disabled rules are stored but omitted from the generated CoreDNS Corefile. |
| `dns.rewrites[].mode` | string | `"stop"` | `"stop"`, `"continue"`, or empty | Controls whether CoreDNS stops after a matching rewrite or continues evaluating later rewrite rules. |
| `dns.rewrites[].field` | string | none | `"name"`, `"type"`, `"ttl"`, or `"rcode"` | Selects what the CoreDNS rewrite rule changes. |
| `dns.rewrites[].match` | string | `"exact"` | `"exact"`, `"prefix"`, `"suffix"`, `"substring"`, `"regex"`, or empty | Match type for name, TTL, and RCODE rewrites. Type rewrites ignore this field. Regex patterns must compile and be 10000 characters or fewer. |
| `dns.rewrites[].from` | string | none | Required for enabled rules | Query name/type value to match, depending on `field`. Values must be a single Corefile token. |
| `dns.rewrites[].to` | string | none | Required for name, type, and TTL rewrites | Rewrite target. For TTL rewrites this is seconds such as `"30"` or a range such as `"30-300"`, `"-30"`, or `"30-"`. |
| `dns.rewrites[].rcode_from` | string | none | Supported DNS RCODE name or number | Source response code for RCODE rewrites, such as `"SERVFAIL"`. |
| `dns.rewrites[].rcode_to` | string | none | Supported DNS RCODE name or number | Target response code for RCODE rewrites, such as `"NOERROR"`. |
| `dns.rewrites[].answer_mode` | string | `"none"` | `"none"`, `"auto"`, `"name"`, or `"value"` | Optional CoreDNS answer rewrite behavior for name rewrites. `auto` asks CoreDNS to rewrite answers best-effort so clients see names matching the original question. |
| `dns.rewrites[].answer_from` | string | none | Required when `answer_mode` is `"name"` or `"value"` | Regex source for explicit answer rewrites. |
| `dns.rewrites[].answer_to` | string | none | Required when `answer_mode` is `"name"` or `"value"` | Replacement target for explicit answer rewrites. |
| `dns.rewrites[].comment` | string | empty | Any string | Human-readable note shown in the admin console. |
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
| `logging.level` | string | `"info"` | `"debug"`, `"info"`, `"warn"`, `"warning"`, `"error"`, or empty | Minimum level for Corehole's own stdout/stderr logs. At the default `info` level, Corehole keeps startup-oriented logs only. `debug` also enables admin access logs, CoreDNS query logs, and CoreDNS error stack traces. `warning` is normalized as `warn`. This does not enable CoreDNS debug mode. |
| `logging.format` | string | `"text"` | `"text"`, `"json"`, or empty | Output format for process logs. `json` emits structured JSON objects with named fields for Corehole logs and wraps CoreDNS plugin log lines as JSON. In `debug` mode, CoreDNS query logs use a JSON-shaped query format. |

Cache prefetch uses CoreDNS's popularity-based refresh behavior. With the
defaults, an entry becomes eligible after 5 recent hits with no quiet gap longer
than 60 seconds, then CoreDNS refreshes it near expiry when the remaining TTL is
at or below 10 percent. `cache_prefetch_amount` is not "refresh every N
queries"; it is the hit threshold before prefetch can happen.

SQLite query logging is not exposed as a config flag. Corehole uses
`modernc.org/sqlite`; the driver does not provide a native statement logging
toggle comparable to CoreDNS's `log` plugin. Corehole intentionally avoids
wrapping every repository call just to produce SQL logs.

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
- `dns.cache_success_ttl`, `dns.cache_denial_ttl`, capacities, and prefetch
  fields: used inside the generated CoreDNS `cache` block; restart required
  after YAML changes.
- `dns.rewrites`: used to build CoreDNS `rewrite` directives before default
  forwarding; restart required after YAML changes.
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
- `logging.level`: applied to Corehole/admin logging at startup and used to
  build CoreDNS `errors`/`log` directives; restart required after YAML changes.
- `logging.format`: applied to Corehole logging at startup; restart required
  after YAML changes.

The admin API supports `GET /api/config` in `corehole serve`; it returns the
persisted active configuration, active upstreams, cache settings, DNSSEC mode,
and conditional forwarding settings. `PUT /api/config` saves the persisted
configuration used by later startups.

`PUT /api/config` can persist these JSON fields to the SQLite `app_config`
table:

- `dns.listen`
- `dns.resolvers`
- `dns.cache_success_ttl`
- `dns.cache_denial_ttl`
- `dns.cache_success_capacity`
- `dns.cache_denial_capacity`
- `dns.cache_prefetch_amount`
- `dns.cache_prefetch_duration`
- `dns.cache_prefetch_percent`
- `dns.rewrites`
- `dns.dnssec`
- `dns.conditional_forwarding`
- `admin.listen`
- `blocking.response`
- `blocking.bundled`
- `blocking.blocklists`
- `logging.level`
- `logging.format`

That update path preserves `storage.path`. DNS resolver/cache/DNSSEC,
conditional forwarding, and CoreDNS-relevant `logging.level` changes can apply through DNS hot
reload when the DNS listen address is unchanged and the active update manager
has a DNS reloader. If hot reload is unavailable, if the DNS listen address
changes, or if a change touches `admin.listen`, `logging.level`,
`logging.format`, or configured blocklist paths, the response reports
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
- deprecated `dns.cache_ttl` is negative or greater than `1800`.
- `dns.cache_success_ttl` is negative or greater than `3600`.
- `dns.cache_denial_ttl` is negative or greater than `1800`.
- `dns.cache_success_capacity` or `dns.cache_denial_capacity` is below `1024`
  while cache is enabled.
- cache prefetch fields are negative, or `dns.cache_prefetch_percent` is
  greater than `100`.
- an enabled rewrite rule has an unsupported field/mode/match, missing
  required values, an invalid DNS record type, invalid TTL rewrite target,
  invalid RCODE, or an invalid/overlong regex.
- `logging.level` is unsupported.
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
  cache_success_ttl: 3600
  cache_denial_ttl: 30
  cache_success_capacity: 32768
  cache_denial_capacity: 4096
  cache_prefetch_amount: 5
  cache_prefetch_duration: 60
  cache_prefetch_percent: 10
  rewrites: []
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
logging:
  level: info
  format: text
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
  cache_success_ttl: 3600
  cache_denial_ttl: 30
  cache_success_capacity: 65536
  cache_denial_capacity: 8192
  cache_prefetch_amount: 5
  cache_prefetch_duration: 60
  cache_prefetch_percent: 10
  rewrites:
    - enabled: true
      mode: stop
      field: name
      match: suffix
      from: ".home.arpa."
      to: ".lan."
      answer_mode: auto
      comment: "Map home.arpa names to the LAN resolver namespace"
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
logging:
  level: info
  format: text
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
