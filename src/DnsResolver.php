<?php

declare(strict_types=1);

namespace Azanumer\DnsResolver;

/**
 * Dependency-free DNS client (RFC 1035).
 *
 * Sends a plain DNS query over UDP to a resolver of your choice (default
 * 8.8.8.8) and parses the answer section itself — no ext-dns, no shelling
 * out to dig, no cURL. A truncated (TC) reply is automatically retried
 * over TCP.
 *
 * Supported record types: A, AAAA, CNAME, MX, NS, SOA and TXT. Anything
 * else is returned with its raw RDATA hex-encoded so the caller can still
 * see it.
 */
final class DnsResolver
{
    public const TYPE_A     = 1;
    public const TYPE_NS    = 2;
    public const TYPE_CNAME = 5;
    public const TYPE_SOA   = 6;
    public const TYPE_MX    = 15;
    public const TYPE_TXT   = 16;
    public const TYPE_AAAA  = 28;

    /** @var array<int, string> Record type numbers to names. */
    private const TYPE_NAMES = array(
        self::TYPE_A     => 'A',
        self::TYPE_NS    => 'NS',
        self::TYPE_CNAME => 'CNAME',
        self::TYPE_SOA   => 'SOA',
        self::TYPE_MX    => 'MX',
        self::TYPE_TXT   => 'TXT',
        self::TYPE_AAAA  => 'AAAA',
    );

    /** @var string Resolver IP address (v4 or v6). */
    private string $server;

    /** @var int Resolver port. */
    private int $port;

    /** @var float Seconds to wait for a reply. */
    private float $timeout;

    /** @var int Extra attempts after the first (0 = try once). */
    private int $retries;

    /**
     * @param string $server  Resolver IP address (default Google 8.8.8.8).
     * @param int    $port    Resolver port (default 53).
     * @param float  $timeout Seconds to wait per attempt (default 5.0).
     * @param int    $retries Extra attempts after the first (default 1).
     */
    public function __construct(string $server = '8.8.8.8', int $port = 53, float $timeout = 5.0, int $retries = 1)
    {
        $this->setServer($server);
        $this->port    = $port;
        $this->timeout = $timeout;
        $this->retries = max(0, $retries);
    }

    /**
     * Change the resolver (must be an IP address, not a hostname — you
     * cannot resolve the resolver's own name without a resolver).
     */
    public function setServer(string $server): void
    {
        if (false === filter_var($server, FILTER_VALIDATE_IP)) {
            throw new \InvalidArgumentException('DNS server must be an IP address, got: ' . $server);
        }
        $this->server = $server;
    }

    public function setTimeout(float $timeout): void
    {
        $this->timeout = $timeout;
    }

    /**
     * Query any supported record type.
     *
     * @param string $name Hostname, e.g. 'example.com' (trailing dot ok).
     * @param int    $type One of the TYPE_* constants.
     * @return array<int, array{type: string, ttl: int, data: mixed}> Records in
     *         answer order. Empty array when the name exists but has no
     *         records of this type, or when the name does not exist
     *         (NXDOMAIN). Throws DnsResolverException on transport or
     *         protocol errors.
     */
    public function query(string $name, int $type): array
    {
        $name   = $this->normaliseName($name);
        $id     = random_int(0, 65535);
        $packet = $this->buildQuery($id, $name, $type);

        $lastError = null;
        for ($attempt = 0; $attempt <= $this->retries; $attempt++) {
            try {
                $response = $this->sendUdp($packet);
            } catch (DnsResolverException $e) {
                $lastError = $e;
                continue;
            }
            return $this->parseResponse($response, $id);
        }

        throw $lastError;
    }

    /** @return string[] IPv4 addresses. */
    public function getARecords(string $name): array
    {
        return $this->pluckData($this->query($name, self::TYPE_A));
    }

    /** @return string[] IPv6 addresses. */
    public function getAAAARecords(string $name): array
    {
        return $this->pluckData($this->query($name, self::TYPE_AAAA));
    }

    /** @return array<int, array{preference: int, exchange: string}> Lowest preference first. */
    public function getMxRecords(string $name): array
    {
        $records = $this->pluckData($this->query($name, self::TYPE_MX));
        usort($records, function (array $a, array $b): int {
            return $a['preference'] <=> $b['preference'];
        });
        return $records;
    }

    /** @return string[] TXT strings (one entry per record). */
    public function getTxtRecords(string $name): array
    {
        return $this->pluckData($this->query($name, self::TYPE_TXT));
    }

    /** @return string[] Name server hostnames. */
    public function getNsRecords(string $name): array
    {
        return $this->pluckData($this->query($name, self::TYPE_NS));
    }

    /** Canonical name, or null when the name has no CNAME. */
    public function getCname(string $name): ?string
    {
        $records = $this->query($name, self::TYPE_CNAME);
        return isset($records[0]) ? (string) $records[0]['data'] : null;
    }

    /**
     * Convenience lookup: A + AAAA addresses for a hostname.
     *
     * @return array{a: string[], aaaa: string[]}
     */
    public function resolve(string $name): array
    {
        return array(
            'a'    => $this->getARecords($name),
            'aaaa' => $this->getAAAARecords($name),
        );
    }

    /**
     * Validate and normalise a hostname: strip a trailing dot, lowercase,
     * reject empty labels and over-long names.
     */
    private function normaliseName(string $name): string
    {
        $name = strtolower(rtrim(trim($name), '.'));
        if ('' === $name || strlen($name) > 253) {
            throw new \InvalidArgumentException('Invalid hostname: ' . $name);
        }
        foreach (explode('.', $name) as $label) {
            if ('' === $label || strlen($label) > 63 || !preg_match('/^[a-z0-9-]+$/', $label)) {
                throw new \InvalidArgumentException('Invalid hostname: ' . $name);
            }
        }
        return $name;
    }

    /**
     * Build a standard query packet: 12-byte header (RD set, one question)
     * + QNAME as length-prefixed labels + QTYPE + QCLASS (IN = 1).
     */
    private function buildQuery(int $id, string $name, int $type): string
    {
        $packet = pack('nnnnnn', $id, 0x0100, 1, 0, 0, 0);
        foreach (explode('.', $name) as $label) {
            $packet .= chr(strlen($label)) . $label;
        }
        $packet .= "\x00" . pack('nn', $type, 1);
        return $packet;
    }

    /**
     * Send one UDP datagram and read the reply. Throws on connect failure,
     * write failure or timeout (empty read).
     */
    private function sendUdp(string $packet): string
    {
        $socket = @fsockopen('udp://' . $this->server, $this->port, $errno, $errstr, $this->timeout);
        if (false === $socket) {
            throw new DnsResolverException('Could not reach DNS server ' . $this->server . ': ' . $errstr);
        }
        stream_set_timeout($socket, (int) ceil($this->timeout));
        if (false === fwrite($socket, $packet)) {
            fclose($socket);
            throw new DnsResolverException('Failed to send DNS query to ' . $this->server);
        }
        $response = fread($socket, 4096);
        fclose($socket);
        if (false === $response || '' === $response) {
            throw new DnsResolverException('Timed out waiting for DNS server ' . $this->server);
        }
        // Truncated reply (TC bit): retry the same query over TCP.
        if (strlen($response) >= 4 && (ord($response[2]) & 0x02)) {
            return $this->sendTcp($packet);
        }
        return $response;
    }

    /**
     * DNS over TCP: 2-byte length prefix, then the query; the reply is the
     * same length-prefixed format.
     */
    private function sendTcp(string $packet): string
    {
        $socket = @fsockopen('tcp://' . $this->server, $this->port, $errno, $errstr, $this->timeout);
        if (false === $socket) {
            throw new DnsResolverException('Could not reach DNS server over TCP ' . $this->server . ': ' . $errstr);
        }
        stream_set_timeout($socket, (int) ceil($this->timeout));
        fwrite($socket, pack('n', strlen($packet)) . $packet);
        $lenBytes = fread($socket, 2);
        if (false === $lenBytes || 2 !== strlen($lenBytes)) {
            fclose($socket);
            throw new DnsResolverException('Short TCP reply from DNS server ' . $this->server);
        }
        $length   = unpack('n', $lenBytes)[1];
        $response = '';
        while (strlen($response) < $length) {
            $chunk = fread($socket, $length - strlen($response));
            if (false === $chunk || '' === $chunk) {
                break;
            }
            $response .= $chunk;
        }
        fclose($socket);
        if (strlen($response) !== $length) {
            throw new DnsResolverException('Truncated TCP reply from DNS server ' . $this->server);
        }
        return $response;
    }

    /**
     * Parse a DNS response: verify the ID and QR bit, surface the RCODE,
     * skip the question section, then decode every answer record.
     *
     * @return array<int, array{type: string, ttl: int, data: mixed}>
     */
    private function parseResponse(string $response, int $expectedId): array
    {
        if (strlen($response) < 12) {
            throw new DnsResolverException('DNS reply too short (' . strlen($response) . ' bytes)');
        }
        $header = unpack('nid/nflags/nqdcount/nancount/nnscount/narcount', $response);
        if ($header['id'] !== $expectedId) {
            throw new DnsResolverException('DNS reply ID mismatch (expected ' . $expectedId . ')');
        }
        if (!($header['flags'] & 0x8000)) {
            throw new DnsResolverException('DNS reply is not a response (QR bit clear)');
        }
        $rcode = $header['flags'] & 0x000F;
        if (3 === $rcode) {
            return array(); // NXDOMAIN: name does not exist.
        }
        if (0 !== $rcode) {
            throw new DnsResolverException('DNS server returned error RCODE ' . $rcode);
        }

        $offset = 12;
        // Skip the question section(s).
        for ($i = 0; $i < $header['qdcount']; $i++) {
            $this->readName($response, $offset);
            $offset += 4; // QTYPE + QCLASS.
        }

        $records = array();
        for ($i = 0; $i < $header['ancount']; $i++) {
            $records[] = $this->readRecord($response, $offset);
        }
        return $records;
    }

    /**
     * Read one resource record at $offset and advance $offset past it.
     *
     * @return array{type: string, ttl: int, data: mixed}
     */
    private function readRecord(string $msg, int &$offset): array
    {
        $this->readName($msg, $offset);
        if ($offset + 10 > strlen($msg)) {
            throw new DnsResolverException('Truncated resource record in DNS reply');
        }
        $fields    = unpack('ntype/nclass/Nttl/nrdlength', substr($msg, $offset, 10));
        $offset   += 10;
        $rdlength  = $fields['rdlength'];
        $rdataPos  = $offset;
        $offset   += $rdlength;
        if ($offset > strlen($msg)) {
            throw new DnsResolverException('RDATA overruns DNS reply');
        }
        $rdata = substr($msg, $rdataPos, $rdlength);
        $type  = $fields['type'];

        return array(
            'type' => self::TYPE_NAMES[$type] ?? ('TYPE' . $type),
            'ttl'  => $fields['ttl'],
            'data' => $this->parseRdata($type, $rdata, $msg, $rdataPos),
        );
    }

    /**
     * Decode RDATA for the types we understand; anything else is returned
     * hex-encoded so the caller can still inspect it.
     *
     * @return mixed
     */
    private function parseRdata(int $type, string $rdata, string $msg, int $rdataPos)
    {
        switch ($type) {
            case self::TYPE_A:
                if (4 !== strlen($rdata)) {
                    throw new DnsResolverException('Malformed A record (expected 4 bytes)');
                }
                return inet_ntop($rdata);
            case self::TYPE_AAAA:
                if (16 !== strlen($rdata)) {
                    throw new DnsResolverException('Malformed AAAA record (expected 16 bytes)');
                }
                return inet_ntop($rdata);
            case self::TYPE_CNAME:
            case self::TYPE_NS:
                // $rdataPos is the RDATA's absolute offset in the message, so
                // names inside it (and their compression pointers) resolve
                // against the full message, not the slice.
                $pos = $rdataPos;
                return $this->readName($msg, $pos);
            case self::TYPE_MX:
                if (strlen($rdata) < 3) {
                    throw new DnsResolverException('Malformed MX record');
                }
                $preference = unpack('n', substr($rdata, 0, 2))[1];
                $pos        = $rdataPos + 2;
                return array(
                    'preference' => $preference,
                    'exchange'   => $this->readName($msg, $pos),
                );
            case self::TYPE_TXT:
                // One record can hold several length-prefixed strings.
                $text = '';
                $pos  = 0;
                while ($pos < strlen($rdata)) {
                    $len   = ord($rdata[$pos]);
                    $text .= substr($rdata, $pos + 1, $len);
                    $pos  += 1 + $len;
                }
                return $text;
            case self::TYPE_SOA:
                $pos = $rdataPos;
                $soa = array(
                    'mname' => $this->readName($msg, $pos),
                    'rname' => $this->readName($msg, $pos),
                );
                $nums = unpack('Nserial/Nrefresh/Nretry/Nexpire/Nminimum', substr($msg, $pos, 20));
                return array_merge($soa, $nums ?: array());
            default:
                return bin2hex($rdata);
        }
    }

    /**
     * Read a (possibly compressed) domain name starting at $offset.
     *
     * Compression pointers (first two bits 11) jump to another offset in
     * the message; $offset only advances past the bytes actually consumed
     * at the current position, never past a jump target.
     */
    private function readName(string $msg, int &$offset): string
    {
        $labels = array();
        $jumped = false;
        $jumps  = 0;
        $pos    = $offset;

        while (true) {
            if ($pos >= strlen($msg)) {
                throw new DnsResolverException('Name overruns DNS reply');
            }
            $len = ord($msg[$pos]);
            if (0 === $len) {
                $pos++;
                if (!$jumped) {
                    $offset = $pos;
                }
                break;
            }
            if (0xC0 === ($len & 0xC0)) {
                // Compression pointer: 14-bit offset into the message.
                if ($pos + 1 >= strlen($msg)) {
                    throw new DnsResolverException('Truncated compression pointer');
                }
                if (++$jumps > 10) {
                    throw new DnsResolverException('Too many compression pointers (possible loop)');
                }
                if (!$jumped) {
                    $offset = $pos + 2;
                    $jumped = true;
                }
                $pos = (($len & 0x3F) << 8) | ord($msg[$pos + 1]);
                continue;
            }
            if (0 !== ($len & 0xC0)) {
                throw new DnsResolverException('Invalid label length in DNS name');
            }
            $pos++;
            if ($pos + $len > strlen($msg)) {
                throw new DnsResolverException('Label overruns DNS reply');
            }
            $labels[] = substr($msg, $pos, $len);
            $pos     += $len;
        }

        return implode('.', $labels);
    }

    /** @return mixed[] Just the data column of a record list. */
    private function pluckData(array $records): array
    {
        $out = array();
        foreach ($records as $record) {
            $out[] = $record['data'];
        }
        return $out;
    }
}
