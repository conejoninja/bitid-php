CREATE TABLE IF NOT EXISTS `tbl_nonces` (
  `s_ip` varchar(46) COLLATE utf8_bin NOT NULL,
  `dt_datetime` datetime NOT NULL,
  `s_nonce` varchar(32) COLLATE utf8_bin NOT NULL,
  `s_address` varchar(34) COLLATE utf8_bin DEFAULT NULL,
  UNIQUE KEY `s_nonce` (`s_nonce`),
  KEY `dt_datetime` (`dt_datetime`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;
