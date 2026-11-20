# PHP DNS Resolver

A dependency-free DNS client (RFC 1035) — send a query over UDP to any resolver and parse the answer yourself. No `ext-dns`, no shelling out to `dig`, no cURL.

## Usage

```php
require 'src/DnsResolver.php';
require 'src/DnsResolverException.php';

use Azanumer\DnsResolver\DnsResolver;

$resolver = new DnsResolver(); // 8.8.8.8, port 53, 5s timeout, 1 retry

$resolver->getARecords('example.com');    // ['93.184.216.34']
$resolver->getAAAARecords('example.com'); // ['2606:2800:220:1:248:1893:25c8:1946']
$resolver->getMxRecords('gmail.com');     // [['preference' => 5, 'exchange' => 'gmail-smtp-in.l.google.com'], ...]
$resolver->getTxtRecords('example.com');  // ['v=spf1 -all']
$resolver->getCname('www.example.com');  // 'example.com' or null
$resolver->getNsRecords('example.com');   // ['a.iana-servers.net', 'b.iana-servers.net']
$resolver->resolve('example.com');        // ['a' => [...], 'aaaa' => [...]]

// Any type, raw records with TTL:
$resolver->query('example.com', DnsResolver::TYPE_SOA);
// [['type' => 'SOA', 'ttl' => 3600, 'data' => ['mname' => ..., 'serial' => ...]]]
```

## Behaviour

- **NXDOMAIN is not an error** — `query()` returns `[]` when the name does not exist, and when the name exists but has no records of the requested type.
- **Truncated replies (TC bit)** are automatically retried over TCP.
- **Retries**: a timed-out UDP query is retried once by default (`new DnsResolver('1.1.1.1', 53, 5.0, 2)` for two retries).
- **Validation**: the resolver address must be an IP (you can't resolve the resolver's own hostname), and hostnames are validated before any packet is built.
- **Errors** surface as `DnsResolverException`: unreachable server, timeout after all retries, ID mismatch, non-response packet, error RCODE, or a malformed reply.
- **Compression pointers** in names are followed with a 10-jump cap, so a malicious reply can't loop the parser.

## Supported types

A, AAAA, CNAME, MX, NS, SOA, TXT. Any other type is returned with its raw RDATA hex-encoded (`'type' => 'TYPE65'`) so the caller can still inspect it.

## Example

```bash
php examples/dns-example.php example.com
```

## Requirements

- PHP 7.4+
- Outbound UDP port 53 to your chosen resolver (and TCP 53 for truncated replies)

## License

MIT — see [LICENSE](LICENSE).
