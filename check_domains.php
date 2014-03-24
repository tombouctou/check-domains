<?php
require_once 'php-whois/whois.class.php';
if (!isset($argv[1])) {
    echo("please specify input file\n");
    exit(1);
}

$filename = $argv[1];
$d_file = file_get_contents($filename);
$lines = split("\n", $d_file);

class DomainChecker {
    protected static $rmon = array(
        'jan' => '01',
        'feb' => '02',
        'mar' => '03',
        'apr' => '04',
        'may' => '05',
        'jun' => '06',
        'jul' => '07',
        'aug' => '08',
        'sep' => '09',
        'oct' => '10',
        'nov' => '11',
        'dec' => '12',
    );

    public static function getDate($dt) {
        if (is_int($dt))
            return DateTime::createFromFormat('U', $dt);
        $dt = trim(strtolower($dt));
        $rx = '/(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)/';
        if (preg_match($rx, $dt)) {
            $dt = str_replace(
                array_keys(static::$rmon),
                array_values(static::$rmon),
                $dt
            );
        }
        $rx = '/(?P<MON>\d{1,2}) (?P<DAY>\d{1,2}) \d{1,2}:\d{1,2}:\d{1,2} \w{2,4} (?P<YEAR>\d{4})/';
        if (preg_match($rx, $dt, $matches)) {
            $d = $matches['DAY'];
            $m = $matches['MON'];
            $y = $matches['YEAR'];
            $dt = "$d.$m.$y";
        }
        foreach(static::$formats as $fmt) {
            $d = DateTime::createFromFormat($fmt, $dt);
            if (strpos($fmt, ' ') === false && $d) 
                $d->setTime(23, 59, 59);
            if ($d)
                break;
        }   
        return $d; 
    }   

    public static $formats = array(
        'd.m.Y',
        'd-m-Y',
        'd/m/Y',
        'Y-m-d',
        'Y/m/d',
        'Y.m.d',
    );

    public static $rxs = [
        "/(Expires( at)?|Renewal date):\s*(?P<DATE>\d{4}-\d{2}-\d{2})/i",
        "/Expires( at)?:\s*(?P<DATE>\d{2}\/\d{2}\/\d{4})/i",
        "/Domain Expiration Date:\s*\w{3} (?P<DATE>\w{3} \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} \w{2,4} \d{4})/i",
        "/Domain Expiration Date:(?P<DATE>\d{2}-[A-Za-z]{3}-\d{4})/i",
        "/(Registrar Registration )?Expir(ation|y) (D|d)ate:\s*(?P<DATE>\d{2,4}-(\d{2}|[A-Za-z]{3})-\d{2,4}).*/i",
        "/(renewal date|free(-| )date):\s*(?P<DATE>\d{4}\.\d{1,2}\.\d{1,2}).*/i",
    ];

    public static $warnLimit = 15;

    /**
     * Проверить, не истек ли домен
     * @return bool false, если истек или не удалось установить
     */
    public static function check($domain) {
        $w = new whois($domain);
        $info = $w->info();
        $i_lines = split("\n", $info);
        $matched = false;
        foreach($i_lines as $line) {
            $line = trim($line);
            foreach(static::$rxs as $rx) {
                $matches = array();
                if (preg_match($rx, $line, $matches)) {
                    $matched = true;
                    // debug
                    // echo "$domain: {$matches['DATE']}\n";
                    if (isset($matches['DATE']) && ($d = static::getDate($matches['DATE']))) {
                        $nd = new DateTime();
                        $days = $nd->diff($d)->days;
                        if ($days > static::$warnLimit) {
                            return true;
                        }
                    } else {
                        fprintf(STDERR, "%s", "bad date '{$matches['DATE']}' for domain $domain\n");
                        return false;
                    }
                    break 2;
                }
            }
        }
        if (!$matched) {
            //fprintf(STDERR, "%s", $info);
            echo " ERR ";
        }
        return false;
    }

    /**
     * Проверить истечение множества доменов
     */
    public static function checkMany($domains) {
        $ok = true;
        foreach($domains as $domain) {
            if (!$domain || $domain[0] == '-')
                continue;
            if (!static::check($domain)) {
                echo "$domain\n";
                $ok = false;
            }
        }
        return $ok;
    }
}

if (DomainChecker::checkMany($lines)) {
    die("OK\n");
}
?>
