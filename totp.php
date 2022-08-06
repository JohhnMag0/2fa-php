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
include('qrcode.php');


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

    private function Hash($key, $count, $algorithm) {
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
    
    private function Token($hash, $length) {
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
    public function OTP($key, $time = 30, $length = 6, $algorithm = 'sha1', $ntp = true) {
        $time = $this->ByteTime($time, $ntp);
        $hash = $this->Hash($key, $time, $algorithm);
        $token= $this->Token($hash, $length);

        return $token;
    }

    // Generate URI based on Google Authenticator standard
    // <https://github.com/google/google-authenticator/wiki/Key-Uri-Format>
    public function URI($key, $user, $issuer, $period = 30, $algorithm = 'sha1', $digits = 6) {
        $secret = Base::b32encode($key);
        $URI = "otpauth://totp/$user?secret=$secret&issuer=$issuer&algorithm=$algorithm&digits=$digits&period=$period";

        return $URI;
    }

    // Create the QRCode as a gif image 
    public function QRCodeImage($uri, $path = 'qrcode.gif') {
        $qr = new QRCode();

        //Defines the size of the QRCode
        $qr->setTypeNumber(10);

        //Creates the QRCode
        $qr->addData($uri);
        $qr->make();
        $image = $qr->createImage();

        imagegif($image, $path);
    }

    // Create the QRCode to use in HTML
    public function QRCodeHTML($uri) {
        $qr = new QRCode();
        $qr->setTypeNumber(10);
        $qr->addData($uri);
        $qr->make();

        $html = $qr->printHTML();

        return $html;
    }

}
