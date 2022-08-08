<?php
/* ************************************************
 *  Library for base32 encoding and decoding usage 
 *  According to RFC 4648.
 *  <https://datatracker.ietf.org/doc/html/rfc4648>
 *
 *  Name:    Base
 *  Author:  John Mago0
 *  Date:    2022-08-04
 *  Version: 1 
 *
 *  TODO: Add base16 encode and decode.
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

class Base {

    const b32alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public static function b32encode($data){
        $result = '';
        $string = str_split($data);

        // Variables for bit values 
        $remainder = 0;
        $remainderSize = 0;

        foreach ($string as $char) {
            $ascii = ord($char);

            // Move one byte and add a character value
            $remainder = ($remainder << 8) | $ascii;

            // Add a byte to Size
            $remainderSize += 8;
            
            while ($remainderSize > 4) {
                
                // Remove the B32 code portion
                $remainderSize -= 5;

                // @value 31 is the number os chars in the alphabet
                // Get the character bit mask
                $code = $remainder & (31 << $remainderSize);
                // Put the bits in the range of the b32 alphabet
                $code >>= $remainderSize;
                $result .= self::b32alphabet[$code];
            }    
        }

        // Get the value of the bits that are left
        if ($remainderSize > 0) {
            $remainder <<= (5 - $remainderSize);
            $code = $remainder & 31;
            $result .= self::b32alphabet[$code];
        }
        
        return $result;
    }

    public static function b32decode($data){
        $result = '';
        $data = strtoupper($data);
        $byte = 0;
        $byteSize = 0;

        $string = str_split($data);
        foreach ($string as $char) {

            // Get the value of the char within the alphabet
            $validChar = stripos(self::b32alphabet, $char);
            
            // Verify if the data is valid
            if ($validChar === false) {
                exit('Invalid char: '.$char);
            }

            // Move 5 bits and adds the value of the char
            $byte = ($byte << 5) | $validChar;

            // Add the size of one B32 char 
            $byteSize += 5;

            if ($byteSize > 7) {
                
                // Remove one byte
                $byteSize -= 8;

                // Moves the bits to match the ASCII code
                $result .= chr($byte >> $byteSize);
            }
        }

        return $result;
    }
}
