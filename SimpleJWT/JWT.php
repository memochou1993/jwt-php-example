<?php
namespace SimpleJWT;

class JWT
{
    private static $alg = 'HS256';

    private static $supported_algs = [
        'HS256' => 'sha256',
    ];

    public static function base64UrlEncode($data)
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    public static function base64UrlDecode($data)
    {
        $remainder = strlen($data) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $data .= str_repeat('=', $padlen);
        }
        return base64_decode(strtr($data, '-_', '+/'));
    }

    public static function encode(array $payload, string $secret): string
    {
        $header = ['alg' => self::$alg, 'typ' => 'JWT'];

        $headerEncoded  = self::base64UrlEncode(json_encode($header));
        $payloadEncoded = self::base64UrlEncode(json_encode($payload));

        $signature = hash_hmac(
            self::$supported_algs[self::$alg],
            "$headerEncoded.$payloadEncoded",
            $secret,
            true
        );

        $signatureEncoded = self::base64UrlEncode($signature);

        return "$headerEncoded.$payloadEncoded.$signatureEncoded";
    }

    /**
     * @throws JWTException
     */
    public static function decode(string $jwt, string $secret): array
    {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            throw new JWTException('Invalid segment count.');
        }

        [$headerEncoded, $payloadEncoded, $signatureEncoded] = $parts;

        $header  = json_decode(self::base64UrlDecode($headerEncoded), true);
        $payload = json_decode(self::base64UrlDecode($payloadEncoded), true);
        $signature = self::base64UrlDecode($signatureEncoded);

        if (!$header || !$payload) {
            throw new JWTException('Invalid header or payload encoding.');
        }
        
        if (!isset($header['alg']) || !isset(self::$supported_algs[$header['alg']])) {
            throw new JWTException('Unsupported algorithm.');
        }

        $expected_signature = hash_hmac(
            self::$supported_algs[$header['alg']],
            "$headerEncoded.$payloadEncoded",
            $secret,
            true
        );

        // Use hash_equals to prevent timing attacks
        if (!hash_equals($expected_signature, $signature)) {
            throw new JWTException('Invalid signature.');
        }

        // Verify the expiration time
        if (isset($payload['exp']) && time() > $payload['exp']) {
            throw new JWTException('Expired token.');
        }

        return $payload;
    }
}
