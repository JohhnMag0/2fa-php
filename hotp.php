<?php
/* ************************************************
 *  Generates a code that changes according to the
 *  usage count. According to RFC 4226.
 *  <https://datatracker.ietf.org/doc/html/rfc4226>
 *
 *
 *  Author:  John Mago0
 *  Date:    2022-08-03
 *  Version: Alpha  
 * ***********************************************/

// Transform the count on a 8 byte variable
function ByteCount($count = 0) {
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

// @algorithm accepts only sha type algorithm
function GenerateHash($key, $count, $algorithm = 'sha1') {
	$hash = hash_hmac($algorithm, $count, $key);
	return $hash;
}

function GenerateToken($hash, $length) {
	// Turn the hash in a decimal 
	$decimal = [];
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

