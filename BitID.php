<?php
/*
Copyright 2014 Daniel Esteban

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

if (extension_loaded('gmp')) {
    define('USE_EXT', 'GMP');
} else {
    die('GMP extension required.'); // It may be available in a package called "php5-gmp" or similar for your system
}

/**
 * Class BitID
 */
class BitID {

    private $_scheme = "bitid";
    private $_qrservice = "https://chart.googleapis.com/chart?cht=qr&chs=300x300&chl=";

    private $_nonce;
    private $_callback;
    private $_secure = true;

    private $_secp256k1;
    private $_secp256k1_G;

    public function __construct() {
        // curve definition
        // http://www.secg.org/download/aid-784/sec2-v2.pdf
        $this->_secp256k1 = new CurveFp(
            '0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F', '0', '7');
        $this->_secp256k1_G = new Point($this->_secp256k1,
            '0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798',
            '0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8',
            '0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');

    }

    /**
     * Generate a nonce, random string
     *
     * @param int $length
     * @return string
     */
    public function generateNonce($length = 16) {
        return bin2hex(openssl_random_pseudo_bytes($length));
    }

    /**
     * Extract nonce from bitid url
     * @param $uri
     * @return string
     */
    public function extractNonce($uri) {
        if(preg_match('/(&|\?)x=([^&]+)/', $uri . '&', $match)) {
            return $match[2];
        }
        return '';
    }

    /**
     * Generate url for QR code
     *
     * @param $uri
     * @return string
     */
    public function qrCode($uri) {
        return $this->_qrservice . urlencode($uri);
    }

    /**
     * Generate bitid:// url for the callback
     * If nonce is not provided, one will be generated
     *
     * @param $callback
     * @param null $nonce
     * @return string
     */
    public function buildURI($callback, $nonce = null) {
        $this->_callback = $callback;
        if($nonce===null) {
            $this->_nonce = $this->generateNonce();
        } else {
            $this->_nonce = $nonce;
        }

        if(stripos($callback, 'https://')!==false) {
            $this->_callback = str_replace('https://', '', $this->_callback);
            $this->_secure = true;
        } else if(stripos($callback, 'http://')!==false) {
            $this->_callback = str_replace('http://', '', $this->_callback);
            $this->_secure = false;
        }

        return $this->_scheme . '://' . $this->_callback . '?x=' . $this->_nonce . (!$this->_secure?'&u=1':'');
    }

    /**
     * Check if a Bitcoin address is valid or not
     * $testnet is optional if you're using a testnet address, by default it will use the real blockchain
     *
     * @param $address
     * @param bool $testnet
     * @return bool
     */
    public function isAddressValid($address, $testnet = false) {
        try {
            $address = $this->_base58check_decode($address, $testnet);
        } catch(InvalidArgumentException $e) {
            return false;
        }
        if (strlen($address) != 21 || ($address[0] != "\x0" && !$testnet) || ($address[0] != "\x6F" && $testnet)) {
            return false;
        }
        return true;
    }

    /**
     * Same function as isMessageSignatureValid but will not throw any Exception
     * only use this if you're a lazy developer that doesn't handle exceptions
     *
     * @param $address
     * @param $signature
     * @param $message
     * @param bool $testnet
     * @return bool
     */
    public function isMessageSignatureValidSafe($address, $signature, $message, $testnet = false) {
        try {
            return $this->isMessageSignatureValid($address, $signature, $message, $testnet);
        } catch(InvalidArgumentException $e) {
            return false;
        }
    }

    /**
     * Check if a signature is valid
     *
     * @param $address
     * @param $signature
     * @param $message
     * @param bool $testnet
     * @return bool
     * @throws InvalidArgumentException
     */
    public function isMessageSignatureValid($address, $signature, $message, $testnet = false) {
        // extract parameters
        $address = $this->_base58check_decode($address, $testnet);
        if (strlen($address) != 21 || ($address[0] != "\x0" && !$testnet) || ($address[0] != "\x6F" && $testnet)) {
            throw new InvalidArgumentException('invalid Bitcoin address');
        }

        $signature = base64_decode($signature, true);
        if ($signature === false) {
            throw new InvalidArgumentException('invalid base64 signature');
        }

        if (strlen($signature) != 65) {
            throw new InvalidArgumentException('invalid signature length');
        }

        $recoveryFlags = ord($signature[0]) - 27;
        if ($recoveryFlags < 0 || $recoveryFlags > 7) {
            throw new InvalidArgumentException('invalid signature type');
        }
        $isCompressed = ($recoveryFlags & 4) != 0;

        // hash message, recover key
        $messageHash = hash('sha256', hash('sha256', "\x18Bitcoin Signed Message:\n" . $this->_numToVarIntString(strlen($message)).$message, true), true);
        $pubkey = $this->_recoverPubKey($this->_bin2gmp(substr($signature, 1, 32)), $this->_bin2gmp(substr($signature, 33, 32)), $this->_bin2gmp($messageHash), $recoveryFlags, $this->_secp256k1_G);
        if ($pubkey === false) {
            throw new InvalidArgumentException('unable to recover key');
        }
        $point = $pubkey->getPoint();

        // see that the key we recovered is for the address given
        if (!$isCompressed) {
            $pubBinStr = "\x04" . str_pad($this->_gmp2bin($point->getX()), 32, "\x00", STR_PAD_LEFT) .
                str_pad($this->_gmp2bin($point->getY()), 32, "\x00", STR_PAD_LEFT);
        } else {
            $pubBinStr =	($this->_isBignumEven($point->getY()) ? "\x02" : "\x03") .
                str_pad($this->_gmp2bin($point->getX()), 32, "\x00", STR_PAD_LEFT);
        }
        if(!$testnet) {
            $derivedAddress = "\x00". hash('ripemd160', hash('sha256', $pubBinStr, true), true);
        } else {
            $derivedAddress = "\x6F". hash('ripemd160', hash('sha256', $pubBinStr, true), true);
        }

        return $address === $derivedAddress;
    }

    /**
     * @param $bnStr
     * @return bool
     */
    private function _isBignumEven($bnStr) {
        return (((int)$bnStr[strlen($bnStr)-1]) & 1) == 0;
    }

    /**
     * based on bitcoinjs-lib's implementation
     * and SEC 1: Elliptic Curve Cryptography, section 4.1.6, "Public Key Recovery Operation".
     * http://www.secg.org/download/aid-780/sec1-v2.pdf
     *
     * @param $r
     * @param $s
     * @param $e
     * @param $recoveryFlags
     * @param $G
     * @return bool|PublicKey
     */
    function _recoverPubKey($r, $s, $e, $recoveryFlags, $G) {
        $isYEven = ($recoveryFlags & 1) != 0;
        $isSecondKey = ($recoveryFlags & 2) != 0;
        $curve = $G->getCurve();
        $signature = new Signature($r, $s);

        // Precalculate (p + 1) / 4 where p is the field order
        static $p_over_four; // XXX just assuming only one curve/prime will be used
        if (!$p_over_four) {
            $p_over_four = gmp_div(gmp_add($curve->getPrime(), 1), 4);
        }

        // 1.1 Compute x
        if (!$isSecondKey) {
            $x = $r;
        } else {
            $x = gmp_add($r, $G->getOrder());
        }

        // 1.3 Convert x to point
        $alpha = gmp_mod(gmp_add(gmp_add(gmp_pow($x, 3), gmp_mul($curve->getA(), $x)), $curve->getB()), $curve->getPrime());
        $beta = NumberTheory::modular_exp($alpha, $p_over_four, $curve->getPrime());

        // If beta is even, but y isn't or vice versa, then convert it,
        // otherwise we're done and y == beta.
        if ($this->_isBignumEven($beta) == $isYEven) {
            $y = gmp_sub($curve->getPrime(), $beta);
        } else {
            $y = $beta;
        }

        // 1.4 Check that nR is at infinity (implicitly done in construtor)
        $R = new Point($curve, $x, $y, $G->getOrder());

        $point_negate = function($p) { return new Point($p->curve, $p->x, gmp_neg($p->y), $p->order); };

        // 1.6.1 Compute a candidate public key Q = r^-1 (sR - eG)
        $rInv = NumberTheory::inverse_mod($r, $G->getOrder());
        $eGNeg = $point_negate(Point::mul($e, $G));
        $Q = Point::mul($rInv, Point::add(Point::mul($s, $R), $eGNeg));

        // 1.6.2 Test Q as a public key
        $Qk = new PublicKey($G, $Q);
        if ($Qk->verifies($e, $signature)) {
            return $Qk;
        }

        return false;
    }

    /**
     * @param $str
     * @param bool $testnet
     * @return resource|string
     * @throws InvalidArgumentException
     */
    private function _base58check_decode($str, $testnet = false) {
        // strtr thanks to https://github.com/prusnak/addrgen/blob/master/php/addrgen.php
        // ltrim because leading zeroes can mess up the parsing even if you specify the base..
        $v = gmp_init(ltrim(strtr($str,
            '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',
            '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv'), '0'), 58);
        $v = $this->_gmp2bin($v);
        // for each leading 1, pre-pad the byte array with a 0
        for ($i = 0; $i < strlen($str); $i++) {
            if ($str[$i] != '1') {
                break;
            }
            if(!$testnet) {
                $v = "\x00" . $v;
            } else {
                $v = "\x6F" . $v;
            }
        }

        $checksum = substr($v, -4);
        $v = substr($v, 0, -4);

        $expCheckSum = substr(hash('sha256', hash('sha256', $v, true), true), 0, 4);

        if ($expCheckSum != $checksum) {
            throw new InvalidArgumentException('invalid checksum');
        }

        return $v;
    }

    /**
     * @param $i
     * @return string
     * @throws InvalidArgumentException
     */
    private function _numToVarIntString($i) {
        if ($i < 0xfd) {
            return chr($i);
        } else if ($i <= 0xffff) {
            return pack('Cv', 0xfd, $i);
        } else if ($i <= 0xffffffff) {
            return pack('CV', 0xfe, $i);
        } else {
            throw new InvalidArgumentException('int too large');
        }
    }

    /**
     * @param $binStr
     * @return resource
     */
    private function _bin2gmp($binStr) {
        $v = gmp_init('0');

        for ($i = 0; $i < strlen($binStr); $i++) {
            $v = gmp_add(gmp_mul($v, 256), ord($binStr[$i]));
        }

        return $v;
    }

    /**
     * @param $v
     * @return string
     */
    private function _gmp2bin($v) {
        $binStr = '';

        while (gmp_cmp($v, 0) > 0) {
            list($v, $r) = gmp_div_qr($v, 256);
            $binStr = chr(gmp_intval($r)) . $binStr;
        }

        return $binStr;
    }

}



// Setup-stuff cribbed from index.php in the ECC repo
function __autoload($f) {
    $base = dirname(__FILE__)."/phpecc/";
    $interfaceFile = $base . "classes/interface/" . $f . "Interface.php";

    if (file_exists($interfaceFile)) {
        require_once $interfaceFile;
    }

    $classFile = $base . "classes/" . $f . ".php";
    if (file_exists($classFile)) {
        require_once $classFile;
    }

    $utilFile = $base . "classes/util/" . $f . ".php";
    if (file_exists($utilFile)) {
        require_once $utilFile;
    }
}
