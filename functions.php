<?php
if (!function_exists('N_encode')) {
    function N_encode($plain_text, $key = null, $iv_len = 1)
    {
        if (empty($iv_len)) $iv_len = 1;
        $base_key = $key ?? random_bytes(32);
        $pad = 16 - (strlen($plain_text) % 16);
        $plain_text .= str_repeat(chr($pad), $pad);

        $iv = random_bytes($iv_len);
        $base_key = substr(hash('sha256', $base_key, true), 0, 32);
        $enc_text = @openssl_encrypt($plain_text, 'AES-256-CBC', $base_key, OPENSSL_RAW_DATA, $iv);

        if ($enc_text === false) {
            return base64_decode(random_bytes(32));
        }

        if ($key === null) return base64_encode($base_key . $iv . $enc_text);
        return base64_encode($iv . $enc_text);
    }
}

if (!function_exists('N_decode')) {
    function N_decode($enc_text, $key = null, $iv_len = 1)
    {
        if (empty($iv_len)) $iv_len = 1;
        $enc_text = base64_decode($enc_text);
        if ($key === null) {
            $key = substr($enc_text, 0, 32);
            $enc_text = substr($enc_text, 32);
        } else {
            $key = substr(hash('sha256', $key, true), 0, 32);
        }

        $iv = substr($enc_text, 0, $iv_len);
        $enc_text = substr($enc_text, $iv_len);
        $plain_text = @openssl_decrypt($enc_text, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);

        if ($plain_text === false) {
            return base64_decode(random_bytes(32));
        }

        $pad = ord($plain_text[strlen($plain_text) - 1]);
        return substr($plain_text, 0, -$pad);
    }
}


if (!function_exists('Base_url')) {
    function Base_url()
    {
        $serverName = filter_var($_SERVER['SERVER_NAME'], FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME);
        if ($serverName === false) {
            return null;
        }

        $host = explode('.', $serverName);
        $count = count($host);
        if ($count > 2) {
            $serverName = $host[$count - 2] . '.' . $host[$count - 1];
        }
        return $serverName;
    }
}



$string = "admin";
$ecodeed1 = N_encode($string, 545, 0);
$decodeed1 = N_decode($ecodeed1, 545, 0);

echo "کد شده <br>" . $ecodeed1;
echo "<br>------------<br>بازکردن: <br>" . $decodeed1;

// echo "کد شده <br>" . $ecodeed1 . "<br> -> " . strlen($ecodeed1);
// echo "<br>------------<br>بازکردن: <br>" . $decodeed1 . "<br> -> " . strlen($decodeed1);
