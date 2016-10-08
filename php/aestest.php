<?php

class Util
{
    public static function parseHexStr2Str($hexStr)
    {
        $str = "";

        for ($i = 0, $size = strlen($hexStr) / 2; $i < $size; $i++) {
            $c = hexdec(substr($hexStr, $i * 2, 2));
            $str .= chr($c);
        }

        return $str;
    }

    public static function decrypt($content, $password, $salt)
    {
        $hash = hash_pbkdf2("sha1", $password, $salt, 1000, 32);

        // 打开算法和模式对应的模块
        $td     = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_CBC, '');
        $hex_iv = '00000000000000000000000000000000';
        mcrypt_generic_init($td, Util::parseHexStr2Str($hash), Util::parseHexStr2Str($hex_iv));
        $resultStr = mdecrypt_generic($td, $content);

        // 释放加密模块资源
        mcrypt_generic_deinit($td);
        mcrypt_module_close($td);

        return $resultStr;
    }
}

define("PASSWORD", "12345678");

if (isset($_POST["content"])) {
    $content = $_POST["content"];

    // 前32位是salt
    $salt = substr($content, 0, 32);
    echo "salt = " . $salt . "\n";

    // 剩余的是已加密的内容
    $enContent = substr($content, 32);
    echo "enContent = " . $enContent . "\n";

    $result = Util::decrypt(Util::parseHexStr2Str($enContent), PASSWORD, Util::parseHexStr2Str($salt));
    echo "result = " . $result . "\n";
} else {
    echo "没有内容";
}
