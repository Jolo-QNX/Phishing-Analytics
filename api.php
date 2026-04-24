<?php
declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');

const PH_TIMEZONE = 'Asia/Manila';

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
$sessionId = session_id() ?: 'guest';
session_write_close();

require_once __DIR__ . '/ip.php';

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    http_response_code(405);
    echo json_encode([
        'success' => false,
        'message' => 'Only POST requests are allowed.'
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

try {
    if (!isset($_FILES['gophish_files'], $_FILES['ms365_file'])) {
        throw new RuntimeException('Please upload one or more GoPhish CSV files and one Microsoft 365 CSV file.');
    }

    $gophishFiles = normalizeMultiUpload($_FILES['gophish_files']);
    if ($gophishFiles === []) {
        throw new RuntimeException('Please upload at least one GoPhish CSV file.');
    }

    $ms365File = $_FILES['ms365_file'];
    ensureCsvUpload($ms365File, 'Microsoft 365');

    $gophishData = parseGophishFiles($gophishFiles);
    $ms365Data = parseMs365File($ms365File);

    $preferredCampaignDisplayByCompact = buildPreferredCampaignDisplayMap(
        $gophishData['campaign_display_candidates'],
        $ms365Data['campaign_display_candidates']
    );

    $campaigns = [];
    foreach ($gophishData['campaign_keys_seen'] as $compactKey => $_true) {
        $display = $preferredCampaignDisplayByCompact[$compactKey]
            ?? ($gophishData['campaign_display_candidates'][$compactKey][0] ?? '');
        if ($display !== '') {
            $campaigns[$display] = true;
        }
    }
    $campaigns = array_values(array_keys($campaigns));
    natcasesort($campaigns);
    $campaigns = array_values($campaigns);

    $matched = [];
    $ms365Only = [];

    foreach ($ms365Data['records_by_strict'] as $ms365Record) {
        $gophishRecord = findMatchingGophishRecord($ms365Record, $gophishData);

        $preferredDisplay = $preferredCampaignDisplayByCompact[$ms365Record['campaign_key_compact']]
            ?? $ms365Record['campaign_display'];

        if ($gophishRecord !== null) {
            $finalStatus = deriveFinalStatus((string)$gophishRecord['status_raw'], (string)$ms365Record['status_raw']);
            $dateRaw = $ms365Record['date_raw'];

            if (in_array($finalStatus, ['Clicked Link', 'Opened'], true) && trim((string)$gophishRecord['date_raw']) !== '') {
                $dateRaw = $gophishRecord['date_raw'];
            }

            $matched[] = buildOutputRow([
                'email' => $ms365Record['email'],
                'status' => $finalStatus,
                'ip_address' => chooseBestIpValue([
                    (string)($gophishRecord['ip_address'] ?? ''),
                    (string)($ms365Record['ip_address'] ?? ''),
                ]),
                'subject' => $ms365Record['subject'],
                'campaign_display' => $preferredDisplay,
                'date_raw' => $dateRaw,
            ]);
        } else {
            $ms365Only[] = buildOutputRow([
                'email' => $ms365Record['email'],
                'status' => $ms365Record['status_raw'],
                'ip_address' => $ms365Record['ip_address'],
                'subject' => $ms365Record['subject'],
                'campaign_display' => $preferredDisplay,
                'date_raw' => $ms365Record['date_raw'],
            ]);
        }
    }

    $matched = enrichRowsWithIpInfo($matched, $sessionId);
    $ms365Only = enrichRowsWithIpInfo($ms365Only, $sessionId);

    usort($matched, static fn(array $a, array $b): int => ($b['date_sort'] <=> $a['date_sort']));
    usort($ms365Only, static fn(array $a, array $b): int => ($b['date_sort'] <=> $a['date_sort']));

    $allRows = array_merge($matched, $ms365Only);

    echo json_encode([
        'success' => true,
        'matched' => $matched,
        'ms365Only' => $ms365Only,
        'campaigns' => $campaigns,
        'meta' => [
            'gophish_file_count' => count($gophishFiles),
            'gophish_record_count' => count($gophishData['records_by_strict']),
            'ms365_record_count' => count($ms365Data['records_by_strict']),
            'matched_count' => count($matched),
            'ms365_only_count' => count($ms365Only),
            'available_dates' => collectAvailableDates($allRows),
            'ip_total_count' => count(array_unique(array_filter(array_map(
                static fn(array $row): string => trim((string)($row['ip_address'] ?? '')),
                $allRows
            )))),
            'ip_enriched_count' => count(array_filter($allRows, static function (array $row): bool {
                return trim((string)($row['ip_country'] ?? '')) !== ''
                    || trim((string)($row['ip_org'] ?? '')) !== ''
                    || trim((string)($row['ip_asn'] ?? '')) !== '';
            })),
        ]
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
} catch (Throwable $e) {
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'message' => $e->getMessage(),
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}

function normalizeMultiUpload(array $files): array
{
    $normalized = [];
    if (!isset($files['name']) || !is_array($files['name'])) {
        return $normalized;
    }

    foreach ($files['name'] as $index => $name) {
        if (($files['error'][$index] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
            continue;
        }

        $normalized[] = [
            'name' => (string)($files['name'][$index] ?? ''),
            'type' => (string)($files['type'][$index] ?? ''),
            'tmp_name' => (string)($files['tmp_name'][$index] ?? ''),
            'error' => (int)($files['error'][$index] ?? UPLOAD_ERR_NO_FILE),
            'size' => (int)($files['size'][$index] ?? 0),
        ];
    }

    return $normalized;
}

function ensureCsvUpload(array $file, string $label): void
{
    if (($file['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
        throw new RuntimeException($label . ' CSV upload failed.');
    }

    $tmpName = (string)($file['tmp_name'] ?? '');
    if ($tmpName === '' || (!is_uploaded_file($tmpName) && !is_file($tmpName))) {
        throw new RuntimeException($label . ' CSV file is invalid.');
    }
}

function readCsvAssoc(string $path): array
{
    $handle = fopen($path, 'rb');
    if ($handle === false) {
        throw new RuntimeException('Unable to read CSV file.');
    }

    try {
        $header = fgetcsv($handle);
        if ($header === false) {
            return [];
        }

        $header = array_map(static function ($column): string {
            $column = (string)$column;
            $column = preg_replace('/^\xEF\xBB\xBF/', '', $column);
            return trim($column);
        }, $header);

        $rows = [];
        while (($data = fgetcsv($handle)) !== false) {
            if ($data === [null]) {
                continue;
            }

            $row = [];
            foreach ($header as $index => $columnName) {
                $row[$columnName] = isset($data[$index]) ? trim((string)$data[$index]) : '';
            }
            $rows[] = $row;
        }

        return $rows;
    } finally {
        fclose($handle);
    }
}

function parseGophishFiles(array $files): array
{
    $recordsByStrict = [];
    $recordsByCompact = [];
    $campaignDisplayCandidates = [];
    $campaignKeysSeen = [];

    foreach ($files as $file) {
        ensureCsvUpload($file, 'GoPhish');

        $filenameNoExt = pathinfo((string)$file['name'], PATHINFO_FILENAME);
        $campaignDisplay = extractCampaignFromText($filenameNoExt);
        if ($campaignDisplay === '') {
            $campaignDisplay = trim($filenameNoExt);
        }

        $keys = getCampaignMatchKeys($campaignDisplay);
        if ($keys['strict'] === '' && $keys['compact'] === '') {
            continue;
        }

        $campaignDisplayCandidates[$keys['compact']][] = $campaignDisplay;
        $campaignKeysSeen[$keys['compact']] = true;

        foreach (readCsvAssoc((string)$file['tmp_name']) as $row) {
            $email = normalizeEmail((string)($row['email'] ?? ''));
            if ($email === '') {
                continue;
            }

            $statusRaw = trim((string)($row['status'] ?? ''));
            $dateRaw = firstNonEmpty([
                (string)($row['send_date'] ?? ''),
                (string)($row['modified_date'] ?? ''),
            ]);
$candidate = [
                'email' => $email,
                'campaign_key_strict' => $keys['strict'],
                'campaign_key_compact' => $keys['compact'],
                'campaign_display' => $campaignDisplay,
                'status_raw' => $statusRaw,
                'status_priority' => gophishStatusPriority($statusRaw),
                'ip_address' => chooseBestIpValue([
                    getRowValueByAliases($row, ['ip', 'IP', 'IP Address', 'ip_address', 'Address']),
                ]),
                'date_raw' => $dateRaw,
                'date_sort' => parseDateToTimestamp($dateRaw),
            ];

            $strictLookupKey = buildLookupKey($email, $keys['strict']);
            $compactLookupKey = buildLookupKey($email, $keys['compact']);

            if (!isset($recordsByStrict[$strictLookupKey]) || shouldReplaceRecord($candidate, $recordsByStrict[$strictLookupKey])) {
                $recordsByStrict[$strictLookupKey] = $candidate;
            }

            if (!isset($recordsByCompact[$compactLookupKey]) || shouldReplaceRecord($candidate, $recordsByCompact[$compactLookupKey])) {
                $recordsByCompact[$compactLookupKey] = $candidate;
            }
        }
    }

    return [
        'records_by_strict' => $recordsByStrict,
        'records_by_compact' => $recordsByCompact,
        'campaign_display_candidates' => $campaignDisplayCandidates,
        'campaign_keys_seen' => $campaignKeysSeen,
    ];
}

function parseMs365File(array $file): array
{
    ensureCsvUpload($file, 'Microsoft 365');

    $recordsByStrict = [];
    $campaignDisplayCandidates = [];

    foreach (readCsvAssoc((string)$file['tmp_name']) as $row) {
        $email = normalizeEmail((string)($row['RecipientAddress'] ?? ''));
        if ($email === '') {
            continue;
        }

        $subject = trim((string)($row['Subject'] ?? ''));
        $campaignDisplay = extractCampaignFromText($subject);
        if ($campaignDisplay === '') {
            continue;
        }

        $keys = getCampaignMatchKeys($campaignDisplay);
        if ($keys['strict'] === '' && $keys['compact'] === '') {
            continue;
        }

        $campaignDisplayCandidates[$keys['compact']][] = $campaignDisplay;

        $statusRaw = trim((string)($row['Status'] ?? ''));
        $dateRaw = trim((string)($row['Received'] ?? ''));
        $ipAddress = chooseBestIpValue([
            getRowValueByAliases($row, ['ClientIP', 'Client IP', 'OriginalClientIP', 'Original Client IP', 'SenderIP', 'Sender IP', 'SourceIP', 'Source IP']),
            getRowValueByAliases($row, ['FromIP', 'From IP']),
            getRowValueByAliases($row, ['ToIP', 'To IP']),
            getRowValueByAliases($row, ['IP', 'IP Address', 'ip_address']),
        ]);

        $candidate = [
            'email' => $email,
            'campaign_key_strict' => $keys['strict'],
            'campaign_key_compact' => $keys['compact'],
            'campaign_display' => $campaignDisplay,
            'subject' => $subject,
            'status_raw' => $statusRaw,
            'status_priority' => ms365StatusPriority($statusRaw),
            'ip_address' => $ipAddress,
            'date_raw' => $dateRaw,
            'date_sort' => parseDateToTimestamp($dateRaw),
        ];

        $strictLookupKey = buildLookupKey($email, $keys['strict']);
        if (!isset($recordsByStrict[$strictLookupKey]) || shouldReplaceRecord($candidate, $recordsByStrict[$strictLookupKey])) {
            $recordsByStrict[$strictLookupKey] = $candidate;
        }
    }

    return [
        'records_by_strict' => $recordsByStrict,
        'campaign_display_candidates' => $campaignDisplayCandidates,
    ];
}

function normalizeEmail(string $email): string
{
    $email = trim($email);
    if ($email === '') {
        return '';
    }

    $converted = @iconv('UTF-8', 'ASCII//TRANSLIT//IGNORE', $email);
    if ($converted !== false) {
        $email = $converted;
    }

    $email = strtolower($email);
    $email = filter_var($email, FILTER_SANITIZE_EMAIL);

    return trim($email);
}

function extractCampaignFromText(string $text): string
{
    $text = trim($text);
    if ($text === '') {
        return '';
    }

    if (preg_match_all('/\(([^()]*)\)/', $text, $matches) && !empty($matches[1])) {
        $last = trim((string)end($matches[1]));
        return preg_replace('/\s+/', ' ', $last) ?: '';
    }

    return '';
}

function getCampaignMatchKeys(string $campaign): array
{
    $campaign = trim($campaign);
    if ($campaign === '') {
        return ['strict' => '', 'compact' => ''];
    }

    $converted = @iconv('UTF-8', 'ASCII//TRANSLIT//IGNORE', $campaign);
    if ($converted !== false) {
        $campaign = $converted;
    }

    $campaign = strtolower($campaign);
    $campaign = preg_replace('/[–—]+/u', '-', $campaign);
    $campaign = str_replace('&', ' and ', $campaign);

    // Normalize shorthand and common human input variations.
    $campaign = preg_replace('/\bw\s*[\/_\\\\-]\s*o\b/u', ' without ', $campaign); // w/o, w_o, w-o
    $campaign = preg_replace('/\bwo\b/u', ' without ', $campaign);               // wo
    $campaign = preg_replace('/\bwithout\b/u', ' without ', $campaign);
    $campaign = preg_replace('/\bw\s*[\/_\\\\]\s*/u', ' with ', $campaign);       // w/
    $campaign = preg_replace('/\bwith\b/u', ' with ', $campaign);
    $campaign = preg_replace('/\bw\b/u', ' with ', $campaign);                   // standalone w

    // Strip punctuation and spacing noise while preserving word order.
    $campaign = preg_replace('/[^a-z0-9]+/u', ' ', $campaign);
    $campaign = preg_replace('/\s+/u', ' ', $campaign);
    $campaign = trim((string)$campaign);

    return [
        'strict' => $campaign,
        'compact' => str_replace(' ', '', $campaign),
    ];
}

function buildPreferredCampaignDisplayMap(array $gophishDisplaysByCompact, array $ms365DisplaysByCompact): array
{
    $preferred = [];

    foreach ($ms365DisplaysByCompact as $compactKey => $displays) {
        foreach ($displays as $display) {
            $cleanDisplay = cleanCampaignDisplay((string)$display);
            if ($cleanDisplay !== '') {
                $preferred[$compactKey] = $cleanDisplay;
                break;
            }
        }
    }

    foreach ($gophishDisplaysByCompact as $compactKey => $displays) {
        if (isset($preferred[$compactKey])) {
            continue;
        }

        foreach ($displays as $display) {
            $cleanDisplay = cleanCampaignDisplay((string)$display);
            if ($cleanDisplay !== '') {
                $preferred[$compactKey] = $cleanDisplay;
                break;
            }
        }
    }

    return $preferred;
}

function cleanCampaignDisplay(string $display): string
{
    $display = preg_replace('/\s+/u', ' ', trim($display));
    return $display ?: '';
}

function findMatchingGophishRecord(array $ms365Record, array $gophishData): ?array
{
    $email = (string)($ms365Record['email'] ?? '');
    $strictKey = buildLookupKey($email, (string)($ms365Record['campaign_key_strict'] ?? ''));
    if (isset($gophishData['records_by_strict'][$strictKey])) {
        return $gophishData['records_by_strict'][$strictKey];
    }

    $compactKey = buildLookupKey($email, (string)($ms365Record['campaign_key_compact'] ?? ''));
    if (isset($gophishData['records_by_compact'][$compactKey])) {
        return $gophishData['records_by_compact'][$compactKey];
    }

    return null;
}

function buildLookupKey(string $email, string $campaignKey): string
{
    return $email . '|' . $campaignKey;
}

function gophishStatusPriority(string $status): int
{
    return match (trim($status)) {
        'Clicked Link' => 300,
        'Email Opened' => 200,
        'Email Sent' => 100,
        default => 0,
    };
}

function ms365StatusPriority(string $status): int
{
    return match (trim($status)) {
        'Delivered' => 300,
        'FilteredAsSpam' => 200,
        'Failed' => 100,
        default => 0,
    };
}

function shouldReplaceRecord(array $candidate, array $existing): bool
{
    if (($candidate['status_priority'] ?? 0) !== ($existing['status_priority'] ?? 0)) {
        return ($candidate['status_priority'] ?? 0) > ($existing['status_priority'] ?? 0);
    }

    return ($candidate['date_sort'] ?? 0) > ($existing['date_sort'] ?? 0);
}

function deriveFinalStatus(string $gophishStatus, string $ms365Status): string
{
    $gophishStatus = trim($gophishStatus);
    $ms365Status = trim($ms365Status);

    if ($gophishStatus === 'Clicked Link') {
        return 'Clicked Link';
    }
    if ($gophishStatus === 'Email Opened') {
        return 'Opened';
    }
    if ($ms365Status !== '') {
        return $ms365Status;
    }

    return $gophishStatus !== '' ? $gophishStatus : 'Unknown';
}

function parseDateToTimestamp(?string $date): int
{
    $date = trim((string)$date);
    if ($date === '') {
        return 0;
    }

    try {
        $dt = new DateTime($date);
        return $dt->getTimestamp();
    } catch (Throwable $e) {
        return 0;
    }
}

function normalizeDateForDisplay(?string $date): array
{
    $date = trim((string)$date);
    if ($date === '') {
        return [
            'timestamp' => 0,
            'date_display' => '',
            'date_ph_date' => '',
        ];
    }

    try {
        $dt = new DateTime($date);
        $dt->setTimezone(new DateTimeZone(PH_TIMEZONE));

        return [
            'timestamp' => $dt->getTimestamp(),
            'date_display' => $dt->format('Y-m-d h:i:s A') . ' PHT',
            'date_ph_date' => $dt->format('Y-m-d'),
        ];
    } catch (Throwable $e) {
        return [
            'timestamp' => 0,
            'date_display' => $date,
            'date_ph_date' => '',
        ];
    }
}

function buildOutputRow(array $record): array
{
    $date = normalizeDateForDisplay((string)($record['date_raw'] ?? ''));
    $ipAddress = extractIpValue((string)($record['ip_address'] ?? ''));

    return [
        'email' => (string)($record['email'] ?? ''),
        'status' => (string)($record['status'] ?? ''),
        'ip_address' => $ipAddress,
        'ip_country' => '',
        'ip_org' => '',
        'ip_asn' => '',
        'subject' => (string)($record['subject'] ?? ''),
        'campaign_display' => (string)($record['campaign_display'] ?? ''),
        'date_raw' => (string)($record['date_raw'] ?? ''),
        'date_display' => $date['date_display'],
        'date_ph_date' => $date['date_ph_date'],
        'date_sort' => $date['timestamp'],
    ];
}

function enrichRowsWithIpInfo(array $rows, string $sessionId): array
{
    if ($rows === []) {
        return $rows;
    }

    $ips = [];
    foreach ($rows as &$row) {
        $ip = extractIpValue((string)($row['ip_address'] ?? ''));
        $row['ip_address'] = $ip;
        if ($ip !== '' && filter_var($ip, FILTER_VALIDATE_IP) && !isPrivateOrReservedIp($ip)) {
            $ips[$ip] = true;
        }
    }
    unset($row);

    if ($ips === []) {
        return $rows;
    }

    $ipInfoMap = getIpInfo(array_keys($ips), $sessionId);

    foreach ($rows as &$row) {
        $ip = trim((string)($row['ip_address'] ?? ''));
        $info = $ip !== '' ? ($ipInfoMap[$ip] ?? null) : null;
        $normalized = is_array($info) ? normalizeIpInfoData($info) : ['country' => '', 'org' => '', 'asn' => ''];

        $row['ip_country'] = trim((string)($normalized['country'] ?? ''));
        $row['ip_org'] = trim((string)($normalized['org'] ?? ''));
        $row['ip_asn'] = trim((string)($normalized['asn'] ?? ''));
    }
    unset($row);

    return $rows;
}

function collectAvailableDates(array $rows): array
{
    $dates = [];
    foreach ($rows as $row) {
        $date = trim((string)($row['date_ph_date'] ?? ''));
        if ($date !== '') {
            $dates[$date] = true;
        }
    }

    $dates = array_keys($dates);
    rsort($dates, SORT_STRING);
    return $dates;
}


function chooseBestIpValue(array $values): string
{
    $firstExtracted = '';
    $firstValid = '';

    foreach ($values as $value) {
        $ip = extractIpValue((string)$value);
        if ($ip === '') {
            continue;
        }

        if ($firstExtracted === '') {
            $firstExtracted = $ip;
        }

        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            if ($firstValid === '') {
                $firstValid = $ip;
            }

            if (!isPrivateOrReservedIp($ip)) {
                return $ip;
            }
        }
    }

    return $firstValid !== '' ? $firstValid : $firstExtracted;
}

function getRowValueByAliases(array $row, array $aliases): string
{
    foreach ($aliases as $alias) {
        if (array_key_exists($alias, $row)) {
            $value = trim((string)$row[$alias]);
            if ($value !== '') {
                return $value;
            }
        }
    }

    $normalizedAliases = [];
    foreach ($aliases as $alias) {
        $normalizedAliases[normalizeHeaderName((string)$alias)] = true;
    }

    foreach ($row as $key => $value) {
        if (isset($normalizedAliases[normalizeHeaderName((string)$key)])) {
            $value = trim((string)$value);
            if ($value !== '') {
                return $value;
            }
        }
    }

    return '';
}

function normalizeHeaderName(string $name): string
{
    $name = strtolower(trim($name));
    return preg_replace('/[^a-z0-9]+/', '', $name) ?: '';
}

function firstNonEmpty(array $values): string
{
    foreach ($values as $value) {
        $value = trim((string)$value);
        if ($value !== '') {
            return $value;
        }
    }
    return '';
}
