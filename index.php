<?php
use \Firebase\JWT\JWT;
use Firebase\JWT\Key;

require 'vendor/autoload.php';

class JwtAuth
{
  private static $privateKey = "-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAnboO77sAjIvZmjK0WAPhh/JPCCwjogpqLaVwl/JL7ykLith0
EVKLBFsfFc/DvjGZqmshOKUEStVFerUeauQUGS0Ins045HFf9+6rW2lZjC6/Zi1y
7W3nbr3NybHWt0NzBfWUbFliX5Hhwy8GqCLtsIH6GZykM1mPmjthKxqQGGp4Viwg
xhAKvvNYXaf9tQnoVRTob4/hJRS1gOL4V0iGHVyMzFZ9m5ltI/RSeIiKI77WsB8M
zoKRXEKgzMrNNzL/J39QO++bMRnjBvoDvBW1TMwkje3QHIJZGK+941CtbtjSef6C
cMvve2L35WkJfMG4CJ4Ohs+A+VSiY5tg5CM6kQIDAQABAoIBADxA86vJOHB4jGxH
qnVlJicU/fQVSJeCewVtChJB0ZhPicVE4zIq4kiLtthSQmjJ8fYUbuCAyZ780koK
HtCeyL7FYWGo7G74kLzaREPrfvX6dcvG2Pyy25KGl7LRaUEhVzOTmVu62cXAqQoz
UMuybDLdtHlMSb4EHMPCo2AgCaQJisjA2mC9Pyug4iQ7wj07xvEIn1X8/XbFASdM
itqUOIrNkRKDko5P09Gm+H+p8OMmiJRstqMYdc6c3xzcXbrZOjbgZsz65c3TPbno
VXKLA5T8oNHUmHbreYhuP8syT+0HSkxZy1tsNMzrZPTNm/EZdxmfgvpXw31xmE9u
Hewv33ECgYEA/PzGMnZQclr007ibocbcgEa4gD5gGnSEZX1IdhFKsNctQkDvbmPR
jD+THnL1ldfY3xEDGjFxh5NMrb+kFeTtL5+4nwPu5RFZhKayYKyFKwYGFPPU90MP
atfv5yiG8w3xeuyMrRN4wFVTFYKca6hfHkHsB7Duu0YgUB6rQFszx1sCgYEAn5ri
cVela2Pz6BrS8xc4sYGVddOPh/2jFkI0rxwov1H7zEgyCmnHSLmRkTVcy6unWbaI
Q2+ieSsOGrUtpI5JB+6TI8TEWpR49b1Ek3K0RBcUsf69fc76mFIX+nZhPBUpsMLx
Pk3o4ULvrQyDO3nGWz9opNu9X8Mak55noFPJVYMCgYAeHBeaueopMhoheL9NKdXk
joY2/TWC8IsxaQ/OvZAeK/3+/KuCf+7YulhQL257Pw1YvzWXUHsqn6VoqH5m/LAe
EuxuQJGWQdJdr1lbmCzhSf4/UCXwp9KV7M1ovbISC37KGo1DrCWa/oy86qajSY7I
kx/8alp/f4EpB/1p03D+MQKBgQCDhekQqb9BTe7S2Df55qrra/O0UxC2agcY8pnj
q3rQnki3QM8r0ZtNjM4uMSE1HVEdFtQXbkkfPKG01JS2RCJejPVnxmBgnHVJXBzE
vQNcEQEW5OtWX1gWaaAk36SlFHN0nFCcnStJZhWILwV9343b59bd886MuYSPHTwb
3K/O7QKBgD9IMQGO0/bKVIOkEH1FC1iJeOu0VK/LdeWJTQWsIMkRJ8wZapwm1UTr
YYxQ+CKvkLkIrXRuQvy/zf78cexhhe0RzJmOJ4QolzOT8J6VTNDf/uhcqqVmUU+o
FKWlJ+LDOwdst+3CoiuaJWCaiALdBrA4uG+76020uoUxwb36CGuB
-----END RSA PRIVATE KEY-----";

  private static $publicKey = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnboO77sAjIvZmjK0WAPh
h/JPCCwjogpqLaVwl/JL7ykLith0EVKLBFsfFc/DvjGZqmshOKUEStVFerUeauQU
GS0Ins045HFf9+6rW2lZjC6/Zi1y7W3nbr3NybHWt0NzBfWUbFliX5Hhwy8GqCLt
sIH6GZykM1mPmjthKxqQGGp4ViwgxhAKvvNYXaf9tQnoVRTob4/hJRS1gOL4V0iG
HVyMzFZ9m5ltI/RSeIiKI77WsB8MzoKRXEKgzMrNNzL/J39QO++bMRnjBvoDvBW1
TMwkje3QHIJZGK+941CtbtjSef6CcMvve2L35WkJfMG4CJ4Ohs+A+VSiY5tg5CM6
kQIDAQAB
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
