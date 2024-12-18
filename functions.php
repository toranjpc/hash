<?php
if (!function_exists('N_encode')) {
    function get_rnd_iv($iv_len)
    {
        return random_bytes($iv_len);
    }

    function N_encode($plain_text, $key = 'N@SSEj', $iv_len = 16)
    {
        // افزودن PKCS7 Padding
        $pad = 16 - (strlen($plain_text) % 16);
        $plain_text .= str_repeat(chr($pad), $pad);

        $iv = get_rnd_iv($iv_len);
        $key = substr(hash('sha256', $key, true), 0, 32); // اطمینان از طول کلید 32 بایتی
        $enc_text = openssl_encrypt($plain_text, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
        return base64_encode($iv . $enc_text);
    }
}

if (!function_exists('N_decode')) {
    function N_decode($enc_text, $key = 'N@SSEj', $iv_len = 16)
    {
        $enc_text = base64_decode($enc_text);
        $iv = substr($enc_text, 0, $iv_len);
        $enc_text = substr($enc_text, $iv_len);
        $key = substr(hash('sha256', $key, true), 0, 32); // اطمینان از طول کلید 32 بایتی
        $plain_text = openssl_decrypt($enc_text, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);

        // حذف PKCS7 Padding
        $pad = ord($plain_text[strlen($plain_text) - 1]);
        return substr($plain_text, 0, -$pad);
    }
}



if (!function_exists('Base_url')) {
    function Base_url()
    {
        $Base_url = $_SERVER['SERVER_NAME'];
        $host = explode('.', $Base_url);
        $count = count($host);
        if ($count > 2) $Base_url = $host[$count - 2] . '.' . $host[$count - 1];
        return $Base_url;
    }
}

// $string="admin";
// $ecodeed1 = N_encode($string);
// $decodeed1 = N_decode($ecodeed1);

// echo "<br><br><br><br>کد شده <br>".$ecodeed1."<br> -> ".strlen($ecodeed1)."<br><br>";
// echo "بازکردن: <br>".$decodeed1."<br> -> ".strlen($decodeed1)."<br>------------<br>";