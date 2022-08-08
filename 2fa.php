<?php
/* ************************************************
 *  Generates a code that changes according to the
 *  usage count. According to RFC 4226.
 *  <https://datatracker.ietf.org/doc/html/rfc4226>
 *	
 *	Name:	 2fa
 *  Author:  John Mago0
 *  Date:    2022-08-03
 *  Version: 1
 * ***********************************************
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>
 */


include('base.php');
include('qrcode.php');

class HOTP
{
	// Transform the count on a binary 
	private	function ByteCount($count) {
		$byte_count = [];
		for ($i = 7; $i >= 0; $i--){
			// Transform the first 8 bits in a char, pass to the next 8
			$byte_count[$i] = chr($count & 0xff);
			$count = $count >> 8;
		}

		$str_count = implode($byte_count);

		// Add 0 if necessary
		if (strlen($str_count) < 8) {
			$str_count = str_repeat(chr(0), 8 - strlen($str_count)) . $str_count;
		}
		
		return $str_count;
	}

	protected function Hash($key, $count, $algorithm) {
		// Accepts only sha type algorithms
		$sha = ['sha1','sha256','sha512'];

		if (!in_array($algorithm, $sha)) {
			exit("2fa ERROR! Algorithm ".$algorithm." NOT SUPPORTED. Algorithms accept are sha1, sha256 and sha512");
		}
		else {
			$hash = hash_hmac($algorithm, $count, $key);
			return $hash;
		}
	}

	protected function Token($hash, $length) {
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
	public function OTP($key, $count = 0, $length = 6, $algorithm = 'sha1') {
		$count = $this->ByteCount($count);
		$hash = $this->Hash($key, $count, $algorithm);

		if ($length > 10) {
			exit("2fa ERROR! Number of digits can't be greater than 10");
		}
		
		$token= $this->Token($hash, $length);

		return $token;
	}
	
	// Generate URI based on Google Authenticator standard
	// <https://github.com/google/google-authenticator/wiki/Key-Uri-Format>
	public function URI($key, $user, $issuer, $counter = 0, $algorithm = 'sha1', $digits = 6) {

		if ($digits > 10) {
			exit("2fa ERROR! Number of digits can't be greater than 10");
		}
		
		$secret = Base::b32encode($key);
		$URI = "otpauth://hotp/$user?secret=$secret&issuer=$issuer&algorithm=$algorithm&digits=$digits&counter=$counter";
		
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

	// Creates the QRCode to use in HTML
	public function QRCodeHTML($uri) {
		$qr = new QRCode();
		$qr->setTypeNumber(10);
		$qr->addData($uri);
		$qr->make();
		
		$html = $qr->printHTML();

		return $html;
	}
}

class TOTP extends HOTP
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
            exit('2fa ERROR! NTP = '.$ntp.'. Function accepts only true or false values');
        }

        $binary_timestamp = pack('N*', 0) . pack('N*', floor($unix_time/$period));

        return $binary_timestamp;
    }

    // Glue all the things
    public function OTP($key, $time = 30, $length = 6, $algorithm = 'sha1', $ntp = false) {
        $time = $this->ByteTime($time, $ntp);
        $hash = parent::Hash($key, $time, $algorithm);

        if ($length > 10) {
            exit("2fa ERROR! Number of digits can't be greater than 10");
        }
        
        $token= parent::Token($hash, $length);

        return $token;
    }

    // Generate URI based on Google Authenticator standard
    // <https://github.com/google/google-authenticator/wiki/Key-Uri-Format>
    public function URI($key, $user, $issuer, $period = 30, $algorithm = 'sha1', $digits = 6) {

        if ($digits > 10) {
            exit("2fa ERROR! Number of digits can't be greater than 10");
        }
        
        $secret = Base::b32encode($key);
        $URI = "otpauth://totp/$user?secret=$secret&issuer=$issuer&algorithm=$algorithm&digits=$digits&period=$period";

        return $URI;
    }
}
