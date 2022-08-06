<?php
/* ************************************************
 *  Generates a code that changes according to the
 *  usage count. According to RFC 4226.
 *  <https://datatracker.ietf.org/doc/html/rfc4226>
 *
 *
 *  Author:  John Mago0
 *  Date:    2022-08-03
 *  Version: Alpha.1  
 * ***********************************************/

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

	private	function Hash($key, $count, $algorithm) {
		// Accepts only sha type algorithms
		$sha = ['sha1','sha256','sha512'];

		if (!in_array($algorithm, $sha)) {
			exit("Algorithm ".$algorithm." NOT SUPPORTED. Algorithms accept are sha1, sha256 and sha512");
		}
		else {
			$hash = hash_hmac($algorithm, $count, $key);
			return $hash;
		}
	}

	private	function Token($hash, $length) {
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
		$token= $this->Token($hash, $length);

		return $token;
	}
	
	// Generate URI based on Google Authenticator standard
	// <https://github.com/google/google-authenticator/wiki/Key-Uri-Format>
	public function URI($key, $user, $issuer, $counter = 0, $algorithm = 'sha1', $digits = 6) {
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
