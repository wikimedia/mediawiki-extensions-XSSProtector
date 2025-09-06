<?php
$config = require __DIR__ . '/../vendor/mediawiki/mediawiki-phan-config/src/config.php';

$config['suppress_issue_types'] = array_merge( $config['suppress_issue_types'], [
	'PhanRedefinedClassReference',
	'PhanRedefineClass',
] );

return $config;
