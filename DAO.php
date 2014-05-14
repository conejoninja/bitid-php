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

define('DB_HOST', '');
define('DB_USER', '');
define('DB_PASS', '');
define('DB_NAME', '');

// QUICK AND DIRTY DAO CLASS
class DAO {

    private $_mysqli;
    public function __construct($host = DB_HOST, $user = DB_USER, $pass = DB_PASS, $name = DB_NAME) {
        $this->_mysqli = new mysqli($host, $user, $pass, $name);
    }

    /**
     * Insert nonce + IP in the database to avoid an attacker go and try several nonces
     * This will only allow one nonce per IP, but it could be easily modified to allow severals per IP
     * (this is deleted after an user successfully log in the system, so only will collide if two or more users try to log in at the same time)
     *
     * @param $nonce
     * @param $ip
     * @return bool|mysqli_result
     */
    public function insert($nonce, $ip) {
        $this->deleteIP($ip);
        return $this->_mysqli->query(sprintf("INSERT INTO tbl_nonces (`s_ip`, `dt_datetime`, `s_nonce`) VALUES ('%s', '%s', '%s')", $ip, date('Y-m-d H:i:s'), $nonce));
    }

    /**
     * Update table once the message is signed correctly to allow login
     *
     * @param $nonce
     * @param $address
     * @return bool|mysqli_result
     */
    public function update($nonce, $address) {
        return $this->_mysqli->query(sprintf("UPDATE tbl_nonces SET s_address = '%s' WHERE s_nonce = '%s' ", $address, $nonce));
    }

    /**
     * Clean table from used nonces/address
     *
     * @param $nonce
     * @return bool|mysqli_result
     */
    public function delete($nonce) {
        return $this->_mysqli->query(sprintf("DELETE FROM tbl_nonces WHERE s_nonce = '%s' ", $nonce));
    }

    /**
     * Clean table by IP
     *
     * @param $ip
     * @return bool|mysqli_result
     */
    public function deleteIP($ip) {
        return $this->_mysqli->query(sprintf("DELETE FROM tbl_nonces WHERE s_ip = '%s' ", $ip));
    }

    /**
     * Check if user is logged
     *
     * @param $nonce
     * @param $ip
     * @return bool
     */
    public function address($nonce, $ip) {
        $result = $this->_mysqli->query(sprintf("SELECT * FROM tbl_nonces WHERE s_nonce = '%s' AND s_ip = '%s' LIMIT 1 ", $nonce, $ip));
        if($result) {
            $row = $result->fetch_assoc();
            if(isset($row['s_address']) && $row['s_address']!='') {
                $this->delete($nonce);
                return $row['s_address'];
            }
        }
        return false;
    }

    /**
     * Return IP by nonce, if you want to check that an IP could use this nonce
     *
     * @param $nonce
     * @return bool
     */
    public function ip($nonce) {
        $result = $this->_mysqli->query(sprintf("SELECT * FROM tbl_nonces WHERE s_nonce = '%s' LIMIT 1 ", $nonce));
        if($result) {
            $row = $result->fetch_assoc();
            if(isset($row['s_ip'])) {
                return $row['s_ip'];
            }
        }
        return false;
    }

}
