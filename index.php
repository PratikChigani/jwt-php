<?php
use \Firebase\JWT\JWT;
use Firebase\JWT\Key;

require 'vendor/autoload.php';

class JwtAuth
{
  private static $privateKey = "-----BEGIN RSA PRIVATE KEY-----
-----END RSA PRIVATE KEY-----";

  private static $publicKey = "-----BEGIN PUBLIC KEY-----
-----END PUBLIC KEY-----";

  private static $algorithm = 'RS256';

  private static function base64UrlEncode($data)
  {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
  }

  private static function base64UrlDecode($data)
  {
    return base64_decode(strtr($data, '-_', '+/'));
  }

  private static function encodePayloadValues($payload)
  {
    foreach ($payload as $key => $value) {
      $payload[$key] = self::base64UrlEncode($value);
    }
    return $payload;
  }

  private static function decodePayloadValues($payload)
  {
    foreach ($payload as $key => $value) {
      $payload[$key] = self::base64UrlDecode($value);
    }

    $payload = [
      'UserCredentialId' => $payload['UserCredentialId'] ?? null,
      'BusinessTypeId' => $payload['BusinessTypeId'] ?? null,
      'DeviceId' => $payload['DeviceId'] ?? null,
      'IsdCode' => $payload['IsdCode'] ?? null
    ];

    return $payload;
  }

  public static function generateToken($payload)
  {
    $encodedPayload = self::encodePayloadValues($payload);
    $jwt = JWT::encode($encodedPayload, self::$privateKey, self::$algorithm);
    return self::base64UrlEncode($jwt);
  }

  public static function verifyToken($encodedToken)
  {
    try {
      $jwt = self::base64UrlDecode($encodedToken);

      $decoded = JWT::decode($jwt, new Key(self::$publicKey, 'RS256'));

      $decodedArray = (array) $decoded;

      return self::decodePayloadValues($decodedArray);
    } catch (Exception $e) {
      return "Token verification failed: " . $e->getMessage();
    }
  }


}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $payload = json_decode(file_get_contents('php://input'), true);

  if (isset($payload['action']) && $payload['action'] === 'generate') {
    echo json_encode(['token' => JwtAuth::generateToken($payload['data'])], JSON_PRETTY_PRINT);
  } else if (isset($payload['action']) && $payload['action'] === 'verify') {
    echo json_encode(['decoded' => JwtAuth::verifyToken($payload['token'])], JSON_PRETTY_PRINT);
  }
}
