<?php

declare(strict_types=1);

require __DIR__ . '/../src/DnsResolver.php';
require __DIR__ . '/../src/DnsResolverException.php';

use Azanumer\DnsResolver\DnsResolver;

$resolver = new DnsResolver(); // defaults to 8.8.8.8, 5s timeout, 1 retry

$domain = $argv[1] ?? 'example.com';

try {
    echo 'A records for ' . $domain . ":\n";
    foreach ($resolver->getARecords($domain) as $ip) {
        echo '  ' . $ip . "\n";
    }

    echo 'AAAA records:' . "\n";
    foreach ($resolver->getAAAARecords($domain) as $ip) {
        echo '  ' . $ip . "\n";
    }

    echo "MX records (lowest preference first):\n";
    foreach ($resolver->getMxRecords($domain) as $mx) {
        echo '  ' . $mx['preference'] . ' ' . $mx['exchange'] . "\n";
    }

    echo "TXT records:\n";
    foreach ($resolver->getTxtRecords($domain) as $txt) {
        echo '  ' . $txt . "\n";
    }

    // Raw query for anything else, e.g. NS:
    $ns = $resolver->query($domain, DnsResolver::TYPE_NS);
    echo "NS records:\n";
    foreach ($ns as $record) {
        echo '  ' . $record['data'] . ' (TTL ' . $record['ttl'] . ")\n";
    }
} catch (\Azanumer\DnsResolver\DnsResolverException $e) {
    fwrite(STDERR, 'DNS lookup failed: ' . $e->getMessage() . "\n");
    exit(1);
}
