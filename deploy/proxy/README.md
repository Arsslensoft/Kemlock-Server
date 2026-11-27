# Reverse proxy examples

Kemlock serves the API, the web vault and both WebSocket routes (`/notifications/hub` and
`/kem/v1/live`) on one port, 8080. A proxy forwards one upstream. Each example here is tested in
CI (`.github/workflows/proxy.yml`): it opens a WebSocket through the proxy to a stand-in upstream
and expects the stand-in's message back.

| Proxy | What it needs |
|---|---|
| Caddy | `reverse_proxy kemlock:8080`; WebSocket upgrades pass by default |
| Traefik | A router and a service on port 8080; WebSocket upgrades pass by default |
| nginx | `proxy_http_version 1.1` and the `Upgrade` and `Connection` headers on the two WebSocket routes; `client_max_body_size` at the file limit |
| HAProxy | A long `timeout tunnel`, such as `1h`, so idle WebSockets stay open |

All of them send the client address in `X-Forwarded-For`. Tell Kemlock to believe it, from the
proxy's address only, so rate limits see the real client:

```
IP_HEADER=X-Forwarded-For
KEMLOCK_TRUSTED_PROXIES=<the proxy's address>
```

Kemlock reads every `X-Forwarded-For` line and takes the right-most address that is not a trusted
proxy, so a proxy may add its own line or extend the client's. Still, have the outermost proxy
drop any such header the client sent, so the only addresses in it are the ones your proxies wrote
(HAProxy: `http-request del-header X-Forwarded-For` before `option forwardfor`, as the example
does).

`DOMAIN` must be the public address clients use, because DPoP proofs are checked against it.
The examples terminate TLS at the proxy; where a file says `listen 80` or `bind :80`, add your
certificate (certbot, `bind :443 ssl crt ...`) as its comments show.
