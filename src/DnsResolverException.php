<?php

declare(strict_types=1);

namespace Azanumer\DnsResolver;

/**
 * Thrown when a DNS lookup fails: unreachable server, timeout, malformed
 * reply, or a server-side error RCODE. NXDOMAIN (name does not exist) is
 * not an error — query() returns an empty array for it.
 */
final class DnsResolverException extends \RuntimeException
{
}
