<?php
/* ************************************************
 *  Generates a code that changes according to the
 *  usage count. According to RFC 6238.
 *  <https://datatracker.ietf.org/doc/html/rfc6238>
 *
 *
 *  Author:  John Mago0
 *  Date:    2022-08-04
 *  Version: Alpha
 * ***********************************************/

include('base.php');

class TOTP
{
    // Syncs with google NTP server
    private  function VerifyNTP() {
        
        $sock = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
        socket_connect($sock, 'time.google.com', 123);

        // Request with 48 byte long
        $request = "\010" . str_repeat("\0", 47);
        
        socket_send($sock, $request, strlen($request), 0);
        socket_recv($sock, $response, 48, MSG_WAITALL);
        socket_close($sock);

        // Format the binary as a array
        $packet = unpack('N12', $response);

        // Transform the seconds in UNIX format
        $timestamp = $packet[11]-2208988800;

        return $timestamp;
    }


    private function ByteTime($period, $ntp) {
        if ($ntp === false) {
            $unix_time = time();
        }
        elseif ($ntp === true ) {
            $unix_time = $this->VerifyNTP();
        }
        else {
            exit('ERROR! NTP = '.$ntp.'. Function accepts only true or false values');
        }

        $binary_timestamp = pack('N*', 0) . pack('N*', floor($unix_time/$period));

        return $binary_timestamp;
    }

    private function GenerateHash($key, $count, $algorithm) {
        // Accepts only sha type algorithms
        $sha = ['sha1','sha256','sha512'];

        if (!in_array($algorithm, $sha)) {
            exit("Algorithm NOT SUPPORTED. Algorithms accept are sha1, sha256 and sha512");
        }
        else {
            $hash = hash_hmac($algorithm, $count, $key);
            return $hash;
        }
    }
    
    private function GenerateToken($hash, $length) {
        $decimal = [];
        // Turn the hash in a decimal
        foreach (str_split($hash, 2) as $hex) {
            $decimal[] = hexdec($hex);
        }

        // The Magic Algorithm
        $offset = $decimal[count($decimal) - 1] & 0xf;
        $code = ($decimal[$offset] & 0x7f) << 24
        | ($decimal[$offset+1] & 0xff) << 16
        | ($decimal[$offset+2] & 0xff) << 8
        | ($decimal[$offset+3] & 0xff);
        $token = $code % pow(10, $length);

        // Add the missing 0
        $hotp = str_pad($token, $length, "0", STR_PAD_LEFT);
        return $hotp;
    }

    // Glue all the things
    public function Otp($key, $time = 30, $length = 6, $algorithm = 'sha1', $ntp = true) {
        $time = $this->ByteTime($time, $ntp);
        $hash = $this->GenerateHash($key, $time, $algorithm);
        $token= $this->GenerateToken($hash, $length);

        return $token;
    }

    // Generate URI based on Google Authenticator standard
    // <https://github.com/google/google-authenticator/wiki/Key-Uri-Format>
    public function GenerateURI($key, $user, $issuer, $period = 30, $algorithm = 'sha1', $digits = 6) {
        $secret = Base::b32encode($key);
        $URI = "otpauth://totp/$user?secret=$secret&issuer=$issuer&algorithm=$algorithm&digits=$digits&period=$period";

        return $URI;
    }
}
