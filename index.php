<?php
require_once 'vendor/autoload.php';

use SimpleJWT\JWT;
use SimpleJWT\JWTException;

/**
 * JWT Example
 * 
 * Generate a random 256-bit secret key using the command line:
 * php -r "echo bin2hex(random_bytes(32)) . PHP_EOL;"
 */
$secret = 'my-256-bit-secret';

// Set the token expiration time to 1 hour (3600 seconds)
$ttl = 3600;

// Set the payload data
$payload = [
    'user_id' => 123,
    'role' => 'admin',
    'exp' => time() + $ttl,
];

// Encode the payload into a JWT
$token = JWT::encode($payload, $secret);

echo "JWT: " . $token . PHP_EOL;

// Decode the JWT and verify the signature
try {
    $decoded = JWT::decode($token, '$secret');
    print_r($decoded);
} catch (JWTException $e) {
    echo "Error: " . $e->getMessage();
}
