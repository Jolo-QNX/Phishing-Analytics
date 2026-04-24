<?php
declare(strict_types=1);

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
$__ip_session_id = session_id() ?: 'guest';
session_write_close();

/**
 * Returns:
 * [
 *   '1.2.3.4' => ['country' => 'Philippines', 'org' => 'PLDT', 'asn' => 'AS9299']
 * ]
 */
function getIpInfo(array|string $ips, ?string $sessionIdOverride = null): array
{
    $sessionId = $sessionIdOverride ?: (session_id() ?: 'guest');
    $requested = is_array($ips) ? $ips : [$ips];

    $results = [];
    $lookupQueue = [];
    $cacheFile = __DIR__ . '/ip_cache.json';
    $cache = readJsonFileWithLock($cacheFile);

    $successTtl = 86400 * 14; // 14 days
    $failureTtl = 7200;       // 2 hours

    foreach ($requested as $rawIp) {
        $ip = extractIpValue((string)$rawIp);
        if ($ip === '') {
            continue;
        }

        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            $results[$ip] = normalizeIpInfoData(['country' => 'Invalid IP', 'org' => '', 'asn' => '']);
            continue;
        }

        if (isPrivateOrReservedIp($ip)) {
            $results[$ip] = normalizeIpInfoData(['country' => 'Private/Reserved', 'org' => '', 'asn' => '']);
            continue;
        }

        if (isset($cache[$ip]['timestamp'], $cache[$ip]['data']) && is_array($cache[$ip]['data'])) {
            $cached = normalizeIpInfoData($cache[$ip]['data']);
            $ttl = hasIpInfoData($cached) ? $successTtl : $failureTtl;

            // Do not reuse old malformed cache values like org=IP or ASN=ASCity.
            if ((int)$cache[$ip]['timestamp'] >= (time() - $ttl) && isIpInfoAcceptable($cached, $ip)) {
                $results[$ip] = $cached;
                continue;
            }
        }

        $lookupQueue[$ip] = $ip;
    }

    if ($lookupQueue !== [] && function_exists('curl_init')) {
        // Prefer the JSON API first because the bulk HTML column order can change.
        foreach (array_chunk(array_values($lookupQueue), 35) as $chunk) {
            $jsonResults = getIpInfoFromJsonBatch($chunk);
            foreach ($jsonResults as $ip => $data) {
                $normalized = normalizeIpInfoData($data);
                if (isIpInfoAcceptable($normalized, $ip)) {
                    $results[$ip] = $normalized;
                    unset($lookupQueue[$ip]);
                }
            }
        }

        // Fallback to ipapi bulk, but parse by table headers and reject malformed rows.
        foreach (array_chunk(array_values($lookupQueue), 75) as $chunk) {
            $bulkResults = getIpInfoFromBulk($chunk, $sessionId);
            foreach ($bulkResults as $ip => $data) {
                $normalized = normalizeIpInfoData($data);
                if (isIpInfoAcceptable($normalized, $ip)) {
                    $results[$ip] = $normalized;
                    unset($lookupQueue[$ip]);
                }
            }
        }

        // Final fallback to ipwho.is for consistency if ipapi is rate-limited or partial.
        foreach (array_chunk(array_values($lookupQueue), 35) as $chunk) {
            $whoisResults = getIpInfoFromIpWhoIsBatch($chunk);
            foreach ($whoisResults as $ip => $data) {
                $normalized = normalizeIpInfoData($data);
                if (isIpInfoAcceptable($normalized, $ip)) {
                    $results[$ip] = $normalized;
                    unset($lookupQueue[$ip]);
                }
            }
        }
    }

    foreach (array_values(array_unique(array_map('strval', $requested))) as $rawIp) {
        $ip = extractIpValue($rawIp);
        if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP) || isPrivateOrReservedIp($ip)) {
            continue;
        }

        $data = normalizeIpInfoData($results[$ip] ?? ['country' => '', 'org' => '', 'asn' => '']);
        $results[$ip] = $data;
        $cache[$ip] = [
            'timestamp' => time(),
            'data' => $data,
        ];
    }

    writeJsonFileWithLock($cacheFile, $cache);
    return $results;
}

function getIpInfoFromJsonBatch(array $ips): array
{
    return runJsonIpLookupBatch($ips, static function (string $ip): string {
        return 'https://ipapi.co/' . rawurlencode($ip) . '/json/';
    }, static function (array $decoded): array {
        if (($decoded['error'] ?? false) === true) {
            return ['country' => '', 'org' => '', 'asn' => ''];
        }

        return [
            'country' => $decoded['country_name'] ?? $decoded['country'] ?? '',
            'org' => $decoded['org'] ?? $decoded['asn_org'] ?? $decoded['organisation'] ?? '',
            'asn' => $decoded['asn'] ?? '',
        ];
    });
}

function getIpInfoFromIpWhoIsBatch(array $ips): array
{
    return runJsonIpLookupBatch($ips, static function (string $ip): string {
        return 'https://ipwho.is/' . rawurlencode($ip) . '?fields=success,country,connection';
    }, static function (array $decoded): array {
        if (($decoded['success'] ?? true) === false) {
            return ['country' => '', 'org' => '', 'asn' => ''];
        }

        $connection = is_array($decoded['connection'] ?? null) ? $decoded['connection'] : [];

        return [
            'country' => $decoded['country'] ?? '',
            'org' => $connection['org'] ?? $connection['isp'] ?? '',
            'asn' => $connection['asn'] ?? '',
        ];
    });
}

function runJsonIpLookupBatch(array $ips, callable $urlBuilder, callable $normalizer): array
{
    $results = [];
    if ($ips === [] || !function_exists('curl_multi_init')) {
        return $results;
    }

    $multi = curl_multi_init();
    if ($multi === false) {
        return $results;
    }

    $handles = [];
    foreach ($ips as $ip) {
        $ip = extractIpValue((string)$ip);
        if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP) || isPrivateOrReservedIp($ip)) {
            continue;
        }

        $ch = curl_init();
        if ($ch === false) {
            continue;
        }

        curl_setopt_array($ch, [
            CURLOPT_URL => $urlBuilder($ip),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_TIMEOUT => 25,
            CURLOPT_HTTPHEADER => [
                'Accept: application/json',
            ],
        ]);

        curl_multi_add_handle($multi, $ch);
        $handles[$ip] = $ch;
    }

    try {
        $running = null;
        do {
            $status = curl_multi_exec($multi, $running);
            if ($running) {
                $selected = curl_multi_select($multi, 1.0);
                if ($selected === -1) {
                    usleep(100000);
                }
            }
        } while ($running && $status === CURLM_OK);

        foreach ($handles as $ip => $ch) {
            $response = curl_multi_getcontent($ch);
            if (is_string($response) && trim($response) !== '') {
                $decoded = json_decode($response, true);
                if (is_array($decoded)) {
                    $results[$ip] = normalizeIpInfoData($normalizer($decoded));
                }
            }

            curl_multi_remove_handle($multi, $ch);
            curl_close($ch);
        }
    } finally {
        curl_multi_close($multi);
    }

    return $results;
}

function getIpInfoFromBulk(array $ips, string $sessionId): array
{
    $results = [];
    if ($ips === [] || !function_exists('curl_init')) {
        return $results;
    }

    $url = 'https://app.ipapi.co/bulk/';
    $cookieDir = __DIR__ . '/cookies/' . sanitizePathSegment($sessionId);
    ensureDirectory($cookieDir);
    cleanupOldCookieFiles($cookieDir);

    $cookieFile = $cookieDir . '/ipapi_' . date('Ymd_His') . '_' . safeRandomHex(6) . '.txt';
    $ch = curl_init();
    if ($ch === false) {
        return $results;
    }

    try {
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            CURLOPT_CONNECTTIMEOUT => 15,
            CURLOPT_TIMEOUT => 45,
            CURLOPT_COOKIEJAR => $cookieFile,
            CURLOPT_COOKIEFILE => $cookieFile,
            CURLOPT_HTTPGET => true,
            CURLOPT_HTTPHEADER => [
                'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Referer: https://app.ipapi.co/bulk/',
            ],
        ]);

        $getResponse = curl_exec($ch);
        if (!is_string($getResponse) || trim($getResponse) === '') {
            return $results;
        }

        $csrf = extractCsrfToken($getResponse);
        if ($csrf === '') {
            return $results;
        }

        $postData = http_build_query([
            'csrfmiddlewaretoken' => $csrf,
            'q' => implode(',', array_map(static fn($ip): string => extractIpValue((string)$ip), $ips)),
            'key' => '',
            'output' => 'html',
        ]);

        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $postData,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_COOKIEJAR => $cookieFile,
            CURLOPT_COOKIEFILE => $cookieFile,
            CURLOPT_CONNECTTIMEOUT => 15,
            CURLOPT_TIMEOUT => 60,
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/x-www-form-urlencoded',
                'Origin: https://app.ipapi.co',
                'Referer: https://app.ipapi.co/bulk/',
                'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            ],
        ]);

        $postResponse = curl_exec($ch);
        if (!is_string($postResponse) || trim($postResponse) === '') {
            return $results;
        }

        return parseIpApiHtml($postResponse, $ips);
    } finally {
        curl_close($ch);
        if (is_file($cookieFile)) {
            @unlink($cookieFile);
        }
    }
}

function extractCsrfToken(string $html): string
{
    if (preg_match('/name=["\']csrfmiddlewaretoken["\'][^>]*value=["\']([^"\']+)["\']/i', $html, $matches)) {
        return html_entity_decode($matches[1], ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }

    if (preg_match('/value=["\']([^"\']+)["\'][^>]*name=["\']csrfmiddlewaretoken["\']/i', $html, $matches)) {
        return html_entity_decode($matches[1], ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }

    return '';
}

function parseIpApiHtml(string $html, array $requestedIps): array
{
    $results = [];
    if (trim($html) === '') {
        return $results;
    }

    $requestedMap = [];
    foreach ($requestedIps as $requestedIp) {
        $ip = extractIpValue((string)$requestedIp);
        if ($ip !== '') {
            $requestedMap[$ip] = true;
        }
    }

    libxml_use_internal_errors(true);
    $dom = new DOMDocument();
    if (!$dom->loadHTML($html)) {
        libxml_clear_errors();
        return $results;
    }
    libxml_clear_errors();

    $xpath = new DOMXPath($dom);
    foreach ($xpath->query('//table') as $table) {
        $headers = extractTableHeaders($xpath, $table);

        foreach ($xpath->query('.//tr', $table) as $row) {
            $cells = [];
            foreach ($xpath->query('./td', $row) as $cell) {
                $cells[] = normalizeCellText((string)$cell->textContent);
            }

            if (count($cells) < 2) {
                continue;
            }

            $rowIp = '';
            foreach ($cells as $cellText) {
                $candidateIp = extractIpValue($cellText);
                if ($candidateIp !== '' && isset($requestedMap[$candidateIp])) {
                    $rowIp = $candidateIp;
                    break;
                }
            }

            if ($rowIp === '') {
                continue;
            }

            $mapped = mapIpApiCellsByHeaders($headers, $cells);

            // Headerless fallback: only extract cells with unmistakable values.
            if (!hasIpInfoData($mapped)) {
                $mapped = mapIpApiCellsConservatively($cells, $rowIp);
            }

            $normalized = normalizeIpInfoData($mapped);
            if (isIpInfoAcceptable($normalized, $rowIp)) {
                $results[$rowIp] = $normalized;
            }
        }
    }

    return $results;
}

function extractTableHeaders(DOMXPath $xpath, DOMNode $table): array
{
    $headers = [];
    foreach ($xpath->query('.//tr[th][1]/th', $table) as $headerCell) {
        $headers[] = normalizeCellText((string)$headerCell->textContent);
    }

    return $headers;
}

function mapIpApiCellsByHeaders(array $headers, array $cells): array
{
    $country = '';
    $org = '';
    $asn = '';

    if ($headers === []) {
        return ['country' => '', 'org' => '', 'asn' => ''];
    }

    foreach ($headers as $index => $header) {
        if (!array_key_exists($index, $cells)) {
            continue;
        }

        $headerKey = normalizeHeaderKey($header);
        $value = $cells[$index];

        if ($country === '' && (
            $headerKey === 'country'
            || $headerKey === 'countryname'
            || (str_contains($headerKey, 'country') && !str_contains($headerKey, 'code'))
        )) {
            $country = $value;
            continue;
        }

        if ($org === '' && (
            $headerKey === 'org'
            || $headerKey === 'organization'
            || $headerKey === 'organisation'
            || $headerKey === 'isp'
            || str_contains($headerKey, 'organization')
            || str_contains($headerKey, 'organisation')
        )) {
            $org = $value;
            continue;
        }

        if ($asn === '' && (
            $headerKey === 'asn'
            || $headerKey === 'asnumber'
            || str_contains($headerKey, 'asn')
        )) {
            $asn = $value;
            continue;
        }
    }

    return [
        'country' => $country,
        'org' => $org,
        'asn' => $asn,
    ];
}

function mapIpApiCellsConservatively(array $cells, string $rowIp): array
{
    $country = '';
    $org = '';
    $asn = '';

    foreach ($cells as $cell) {
        if ($asn === '' && preg_match('/\bAS\s*(\d{1,10})\b/i', $cell, $matches)) {
            $asn = 'AS' . $matches[1];
            continue;
        }

    }

    // Do not guess country/org from fixed positions; ipapi's HTML order changes.
    // A wrong value is worse than an empty value because the JSON fallbacks will retry it.
    return [
        'country' => $country,
        'org' => $org,
        'asn' => $asn,
    ];
}

function extractIpValue(string $value): string
{
    $value = trim(html_entity_decode($value, ENT_QUOTES | ENT_HTML5, 'UTF-8'));
    if ($value === '') {
        return '';
    }

    // Strip common wrappers.
    $value = trim($value, " \t\n\r\0\x0B[]()<>,");

    if (filter_var($value, FILTER_VALIDATE_IP)) {
        return $value;
    }

    // IPv4 optionally embedded in text or followed by a port.
    if (preg_match('/\b((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})\b/', $value, $match)) {
        return $match[1];
    }

    // IPv6 with optional brackets and optional port.
    if (preg_match('/\[?([A-F0-9]{1,4}(?::[A-F0-9]{1,4}){2,})(?:\]?:\d+)?/i', $value, $match)) {
        $candidate = $match[1];
        if (filter_var($candidate, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return $candidate;
        }
    }

    return '';
}

function normalizeIpInfoData(array $data): array
{
    $country = sanitizeIpInfoText((string)($data['country'] ?? ''));
    $org = sanitizeIpInfoText((string)($data['org'] ?? ''));
    $asn = sanitizeIpInfoText((string)($data['asn'] ?? ''));

    if (filter_var($country, FILTER_VALIDATE_IP)) {
        $country = '';
    }

    if (filter_var($org, FILTER_VALIDATE_IP)) {
        $org = '';
    }

    if ($asn !== '') {
        if (preg_match('/\bAS\s*(\d{1,10})\b/i', $asn, $matches)) {
            $asn = 'AS' . $matches[1];
        } elseif (preg_match('/^\d{1,10}$/', $asn)) {
            $asn = 'AS' . $asn;
        } else {
            // Prevent bad values like "ASMaramag" caused by wrong HTML column mapping.
            $asn = '';
        }
    }

    return [
        'country' => $country,
        'org' => $org,
        'asn' => $asn,
    ];
}

function sanitizeIpInfoText(string $value): string
{
    $value = html_entity_decode($value, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    $value = strip_tags($value);
    $value = preg_replace('/\s+/', ' ', trim($value));
    return trim((string)$value, " \t\n\r\0\x0B,;|");
}

function hasIpInfoData(array $data): bool
{
    $data = normalizeIpInfoData($data);

    return trim((string)($data['country'] ?? '')) !== ''
        || trim((string)($data['org'] ?? '')) !== ''
        || trim((string)($data['asn'] ?? '')) !== '';
}

function isIpInfoAcceptable(array $data, string $ip): bool
{
    $data = normalizeIpInfoData($data);

    $country = trim((string)($data['country'] ?? ''));
    $org = trim((string)($data['org'] ?? ''));
    $asn = trim((string)($data['asn'] ?? ''));

    if ($country === '' && $org === '' && $asn === '') {
        return false;
    }

    if ($org !== '' && (filter_var($org, FILTER_VALIDATE_IP) || extractIpValue($org) === $ip)) {
        $org = '';
    }

    if ($asn !== '' && !preg_match('/^AS\d{1,10}$/i', $asn)) {
        $asn = '';
    }

    return $country !== '' || $org !== '' || $asn !== '';
}

function isPrivateOrReservedIp(string $ip): bool
{
    return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false;
}

function readJsonFileWithLock(string $path): array
{
    if (!is_file($path)) {
        return [];
    }

    $handle = fopen($path, 'c+');
    if ($handle === false) {
        return [];
    }

    try {
        if (!flock($handle, LOCK_SH)) {
            return [];
        }
        $contents = stream_get_contents($handle);
        flock($handle, LOCK_UN);
        $decoded = json_decode($contents ?: '{}', true);
        return is_array($decoded) ? $decoded : [];
    } finally {
        fclose($handle);
    }
}

function writeJsonFileWithLock(string $path, array $data): void
{
    $handle = fopen($path, 'c+');
    if ($handle === false) {
        return;
    }

    try {
        if (!flock($handle, LOCK_EX)) {
            return;
        }
        ftruncate($handle, 0);
        rewind($handle);
        fwrite($handle, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
        fflush($handle);
        flock($handle, LOCK_UN);
    } finally {
        fclose($handle);
    }
}

function ensureDirectory(string $path): void
{
    if (!is_dir($path)) {
        @mkdir($path, 0777, true);
    }
}

function cleanupOldCookieFiles(string $dir): void
{
    if (!is_dir($dir)) {
        return;
    }

    $cutoff = time() - 86400;
    foreach (glob($dir . '/*.txt') ?: [] as $file) {
        if (is_file($file) && filemtime($file) < $cutoff) {
            @unlink($file);
        }
    }
}

function sanitizePathSegment(string $value): string
{
    $value = preg_replace('/[^a-zA-Z0-9_-]/', '_', $value);
    return trim((string)$value, '_') ?: 'session';
}

function normalizeCellText(string $value): string
{
    return preg_replace('/\s+/', ' ', trim(html_entity_decode($value, ENT_QUOTES | ENT_HTML5, 'UTF-8'))) ?: '';
}

function normalizeHeaderKey(string $header): string
{
    return preg_replace('/[^a-z0-9]+/', '', strtolower(trim($header))) ?: '';
}

function safeRandomHex(int $bytes): string
{
    try {
        return bin2hex(random_bytes($bytes));
    } catch (Throwable $e) {
        return str_replace('.', '', uniqid('', true));
    }
}

if ((php_sapi_name() === 'cli' || !isset($_SERVER['REQUEST_METHOD']) || $_SERVER['REQUEST_METHOD'] === 'GET')
    && basename((string)($_SERVER['SCRIPT_NAME'] ?? '')) === basename(__FILE__)) {
    $target = $_GET['ip'] ?? '';
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(
        getIpInfo($target, $__ip_session_id),
        JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
    );
}
