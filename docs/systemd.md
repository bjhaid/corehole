# Running Corehole with systemd

[contrib/systemd/corehole.service](../contrib/systemd/corehole.service) is an
example Linux service unit. It runs Corehole as a dedicated, unprivileged user,
grants the capability needed to bind DNS port 53, and restricts persistent writes
to `/var/lib/corehole`. The unit and this guide are included in release archives.

## First installation

These commands assume the release archive has been extracted in the current
directory. Create the account only if it does not already exist (the `nologin`
path may differ on your distribution):

```sh
sudo useradd --system --user-group --home-dir /var/lib/corehole --shell /usr/sbin/nologin corehole
sudo install -d -o root -g corehole -m 0750 /etc/corehole
sudo install -d -o corehole -g corehole -m 0750 /var/lib/corehole
sudo install -o root -g root -m 0755 corehole /usr/local/bin/corehole
```

For a new installation, copy `corehole.yaml.example` to
`/etc/corehole/corehole.yaml`, owned by `root:corehole` with mode `0640`. Do not
overwrite an existing configuration. Set these storage paths before first
startup:

```yaml
storage:
  path: /var/lib/corehole/corehole.db
  audit_path: /var/lib/corehole/corehole-audit.db
```

The refresh-job database is created beside the main database automatically.
All databases and any configured local blocklist files must be accessible to
the `corehole` user. Keep writable data under `/var/lib/corehole`; the unit
prevents writes elsewhere and hides home directories. Ensure no other DNS
server is already listening on port 53.

The example configuration binds the admin console to `127.0.0.1:8080`. Use an SSH
tunnel to access it remotely, or deliberately configure a suitable interface
and firewall. See [configuration.md](configuration.md) for configuration details.
After the database has been initialized, persisted settings are authoritative;
editing the bootstrap YAML alone will not change those settings.

Install and start the unit:

```sh
sudo install -o root -g root -m 0644 contrib/systemd/corehole.service /etc/systemd/system/corehole.service
sudo systemctl daemon-reload
sudo systemctl enable --now corehole.service
sudo systemctl status corehole.service
sudo journalctl -u corehole.service -f
```

## Upgrades and availability

Preserve the configuration and databases when replacing the binary. Restart
with `sudo systemctl restart corehole.service`; use `daemon-reload` first if the
unit itself changed. Back up existing units before replacing customized ones.

Filtering plugins initialize in the background, and DNS forwards requests while
they are unavailable. List refreshes are asynchronous; accepted jobs can be
polled and unfinished jobs resume after a restart.

This unit does **not** queue DNS requests across process restarts. Corehole does
not currently support systemd socket activation, so installing a `.socket` unit
alone will not work. There is a short listener outage during a restart, and
clients may retry or time out. Even socket activation cannot guarantee that
clients never time out: client deadlines and socket buffers are finite, and
in-flight requests can be lost. Use a second DNS server if continuous resolver
availability is required.
