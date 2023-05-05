<?php

/**
 * Summary
 */

namespace Kastela;

use Error;
use JsonSerializable;

use function PHPSTORM_META\type;

define("protectionPath", "/api/protection/");
define("vaultPath", "/api/vault/");
define("proxyPath", "/api/proxy");
define("securePath", "/api/secure");
define("cryptoPath", "/api/crypto/");

/**
 * Create a new Kastela Client instance for communicating with the server.
 * Require server information and return client instance.
 * ##### Example
 * ```php
 * $kastelaClient = new Client("server.url", "credentials/ca.crt", "credentials/client.crt", "credentials/client.key", );
 * ```
 */
class Client
{
  public $kastelaUrl;
  /**
   * @ignore
   */
  private $ch;

  /**
   * @param string $kastelaUrl Kastela server url
   * @param string $caCertPath Kastela ca certificate path
   * @param string $clientCertPath Kastela client certificate path
   * @param string $clientKeyPath kastela client key path
   * @return void
   */
  public function __construct(string $kastelaUrl, string $caCertPath, string $clientCertPath, string $clientKeyPath)
  {
    $this->kastelaUrl = $kastelaUrl;

    $ch = curl_init();

    curl_setopt($ch, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
    curl_setopt($ch, CURLOPT_SSLCERT, $clientCertPath);
    curl_setopt($ch, CURLOPT_SSLKEY, $clientKeyPath);
    curl_setopt($ch, CURLOPT_CAINFO, $caCertPath);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HEADER, true);
    $this->ch = $ch;
  }

  /**
   * @ignore
   */
  private function request($method, $url, $body)
  {
    $ch = $this->ch;
    curl_setopt($ch, CURLOPT_URL, $url);
    if (isset($body)) {
      $reqBody = json_encode($body);
    }
    switch ($method) {
      case 'post':
        $body = null;
        if (!empty($reqBody)) {
          $body = $reqBody;
        };
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, null);
        break;
      case 'put':
        curl_setopt($ch, CURLOPT_POST, false);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $reqBody);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'PUT');
        break;
      case 'delete':
        curl_setopt($ch, CURLOPT_POST, false);
        curl_setopt($ch, CURLOPT_POSTFIELDS, null);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'DELETE');
        break;
      default:
        curl_setopt($ch, CURLOPT_POST, false);
        curl_setopt($ch, CURLOPT_POSTFIELDS, null);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, null);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'GET');
        break;
    }
    $res = curl_exec($ch);
    if ($res === false) {
      throw new \Error('Curl error: ' . curl_error($ch), 1);
    }

    list($header, $body) = explode("\r\n\r\n", $res, 2);

    $body = json_decode($body, true);
    if (
      $body === null
      && json_last_error() !== JSON_ERROR_NONE
    ) {
      throw new \Error('Json Decode error: ' . json_last_error_msg());
    }

    if (array_key_exists("error", $body)) {
      throw new \Error($body["error"]);
    }
    return $body;
  }

  /**
   * @param list<CryptoEncryptInput>
   */
  public function cryptoEncrypt(array $input)
  {
    $rawData = $this->request(
      "post",
      $this->kastelaUrl . cryptoPath . "encrypt",
      $input
    );
    return $rawData["ciphertexts"];
  }

  /**
   * @param list<string> $input
   */
  public function cryptoDecrypt(array $input)
  {
    $rawData = $this->request(
      "post",
      $this->kastelaUrl . cryptoPath . "decrypt",
      $input
    );
    return $rawData["plaintexts"];
  }

  /**
   * @param list<CryptoHMACInput> $input
   */
  public function cryptoHMAC(array $input)
  {
    $rawData = $this->request(
      "post",
      $this->kastelaUrl . cryptoPath . "hmac",
      $input
    );
    return $rawData["hashes"];
  }

  /**
   * @param list<CryptoEqualInput> $input
   */
  public function cryptoEqual(array $input)
  {
    $rawData = $this->request(
      "post",
      $this->kastelaUrl . cryptoPath . "equal",
      $input
    );
    return $rawData["result"];
  }

  /**
   * @param list<CryptoSignInput> $input
   */
  public function cryptoSign(array $input)
  {
    $rawData = $this->request(
      "post",
      $this->kastelaUrl . cryptoPath . "sign",
      $input
    );
    return $rawData["signatures"];
  }

  /**
   * @param list<CryptoVerifyInput> $input
   */
  public function cryptoVerify(array $input)
  {
    $rawData = $this->request(
      "post",
      $this->kastelaUrl . cryptoPath . "verify",
      $input
    );
    return $rawData["result"];
  }

  /** Store batch vault data on the server.
   * @param list<VaultStoreInput> $input
   * @return list<list<string>> of vault $token
   * ##### Example
   * ```php
   * $tokens = $kastelaClient->vault_store([new VaultStoreInput("id", ["values1", "values2"])])
   * ```
   */
  public function vaultStore(array $input)
  {
    $url = $this->kastelaUrl . vaultPath . 'store';

    $res = $this->request('post', $url, $input);
    return $res["tokens"];
  }

  /** Search vault data by indexed column.
   * @param VaultFetchInput $input
   * @return list<string>
   * ##### Example
   * ```php
   * // fetch vault data with indexed colum $value "jhon doe", return the list of vault $token/id
   * $tokens = $kastelaClient->vault_fetch(new VaultFetchInput($data["vault_id"], $data["search"], $data["size"] | null, $data["after"] | null));
   * ```
   */
  public function vaultFetch(VaultFetchInput $input)
  {
    $url = $this->kastelaUrl . vaultPath . "fetch";

    $res = $this->request('post', $url, $input);
    return $res["tokens"];
  }

  /** Get batch vault data by vault $token ids.
   * @param list<VaultGetInput> $input
   * @return list<list<mixed>>
   * ##### Example
   * ```php
   * // get vault data
   *  $secrets = $kastelaClient->vault_get(new VaultGetInput("id", ["tokens1", "tokens2"]));
   * ```
   */
  public function vaultGet(array $input)
  {
    $url = $this->kastelaUrl . vaultPath . 'get';

    $res = $this->request('post', $url, $input);
    return $res["values"];
  }

  /** Update vault data by vault $token.
   * @param list<VaultUpdateInput> $input
   * @return void
   * ##### Example
   * ```php
   * $kastelaClient->vault_update([new VaultUpdateInput("id", [new VaultUpdateInputValues("token", ["data"=>"yourUpdateData"])])]);
   * ```
   */
  public function vaultUpdate(array $input)
  {
    $url = $this->kastelaUrl . vaultPath . 'update';
    $this->request('post', $url, $input);
  }

  /** Remove vault data by vault $token.
   * @param list<VaultDeleteInput> $input
   * @return void
   * ##### Example
   * ```php
   * $kastelaClient->vault_delete(new VaultDeleteInput("id", ["token1", "token2"]));
   * ```
   */
  public function vaultDelete(array $input)
  {
    $url = $this->kastelaUrl . vaultPath . 'delete';
    $this->request('post', $url, $input);
  }

  /** Encrypt data protection by protection data ids, which can be used $after storing data or updating data.
   * @param list<ProtectionSealInput> $input
   * @return void
   * ##### Example
   * ```php
   * // protect data with id 1,2,3,4,5
   * kastelaClient->protection_seal([new ProtectionSealInput("id", ["pKey1", "pKey2"])]);
   * ```
   */
  public function protectionSeal(array $input)
  {
    $url = $this->kastelaUrl . protectionPath . 'seal';
    $this->request('post', $url, $input);
  }

  /** Decrypt data protection by protection data ids.
   * @param list<ProtectionOpenInput> $input
   * @return list<list<mixed>> $array of decrypted data refers to ids
   * ##### Example
   * ```php
   * // decrypt data with id 1,2,3,4,5
   * $data = kastelaClient->protection_open(new ProtectionOpenInput("id", ["token1", "token2"])]);
   * ```
   */
  public function protectionOpen(array $input)
  {
    $url = $this->kastelaUrl . protectionPath . 'open';
    $res = $this->request('post', $url, $input);
    return $res["data"];
  }

  /** Initialize secure protection.
   * @param SecureOperation $operation operation secure protection operation mode
   * @param array $protectionIds protectionIds array of protection id
   * @param int $ttl ttl time to live in minutes
   * @return array secure protection credential
   * ##### Example
   * ```php
   * 	// begin secure protection
   * client.secureProtectionInit(["yourProtectionId"], 5)
   * ```
   */
  public function secureProtectionInit(SecureOperation $operation, array $protectionIds, int $ttl)
  {
    $url = $this->kastelaUrl . securePath . '/protection/init';
    $res = $this->request('post', $url, ["operation" => $operation, "protection_ids" => $protectionIds, "ttl" => $ttl]);
    return ["credential" => $res["credential"]];
  }

  /** Commit secure protection.
   * @param string $credential
   * @return void
   * ##### Example
   * ```php
   * 	// commit secure protection
   * client.secureProtectionCommit("yourCredential")
   * ```
   */
  public function secureProtectionCommit(string $credential)
  {
    $url = $this->kastelaUrl . securePath . '/protection/commit';
    $this->request('post', $url, ["credential" => $credential]);
  }

  /** Initialize secure vault.
   * @param SecureOperation $operation operation secure vault operation mode
   * @param array $vaultIds vaultIds array of vault id
   * @param int $ttl ttl time to live in minutes
   * @return array secure vault credential
   * ##### Example
   * ```php
   * 	// begin secure vault
   * client.secureVaultInit(["yourVaultId"], 5)
   * ```
   */
  public function secureVaultInit(SecureOperation $operation, array $vaultIds, int $ttl)
  {
    $url = $this->kastelaUrl . securePath . '/vault/init';
    $res = $this->request('post', $url, ["operation" => $operation, "vault_ids" => $vaultIds, "ttl" => $ttl]);
    return ["credential" => $res["credential"]];
  }

  /** Proxying Request.
   * @param PrivacyProxyRequestType $type request body type "json"|"xml"
   * @param string $url request url
   * @param PrivacyProxyRequestMethod $method request method "get"|"post"
   * @param array $common needed information for protection and vault.
   * $common = [
   *    'protections' => ['_column'=>'protectionId'] protections object list. Define column with prefix as key and protectionId as $value.
   *    'vaults' => ['_column'=>['vaultId', 'selectedVaultColumn']]] vaults object list. Define column with prefix as key and array with id as first index and vault column as second index.
   * ]
   * @param array $options
   * $options = [
   *    'headers' => (array) {object} request headers, use "_" prefix for encrypted column key and data id/token as $value.
   *    'params' => (array) {object} request parameters, use "_" prefix for encrypted column key and data id/token as $value.
   *    'body' => (array) {object} request body, use "_" prefix for encrypted column key and data id/token as $value.
   *    'query' => (array)  {object} request query, use "_" prefix for encrypted column key and data id/token as $value.
   *    'rootTag' => (string) root tag, required for xml type$res = $kastelaClient->privacyProxyRequest($data["type"], $data["url"], $data["method"], $data["common"], $data["options"]);
   * ]
   * ##### Example
   * ```php
   * $res = $kastelaClient->privacyProxyRequest($data["type"], $data["url"], $data["method"], $data["common"], $data["options"]);
   * ```
   */
  public function privacyProxyRequest(PrivacyProxyRequestType $type, string $url, PrivacyProxyRequestMethod $method, array $common, array $options)
  {
    if ($type === "xml") {
      throw new \Error("rootTag is required for xml");
    }
    $kastelUrl = $this->kastelaUrl . proxyPath;
    $res = $this->request('post', $kastelUrl, [
      "type" => $type,
      "url" => $url,
      "method" => $method,
      "common" => $common,
      "options" => $options
    ]);
    return $res;
  }
};

enum SecureOperation: string
{
  case READ = 'READ';
  case WRITE = 'WRITE';
}

enum PrivacyProxyRequestType: string
{
  case json = 'json';
  case xml = 'xml';
}

enum PrivacyProxyRequestMethod: string
{
  case get = 'get';
  case post = 'post';
  case put = 'put';
  case delete = 'delete';
  case patch = 'patch';
}

class VaultStoreInput implements JsonSerializable
{
  public string $vaultID;
  public array $values;

  /**
   *  @param list<mixed> $values
   */
  public function __construct(string $vaultID, array $values)
  {
    $this->vaultID = $vaultID;
    $this->values = $values;
  }

  public function jsonSerialize(): mixed
  {
    return [
      "vault_id" => $this->vaultID,
      "values" => $this->values
    ];
  }
}

class VaultDeleteInput implements JsonSerializable
{
  public string $vaultID;
  public array $tokens;

  /**
   * @param list<string> $tokens
   */
  public function __construct(string $vaultID, array $tokens)
  {
    $this->vaultID = $vaultID;
    $this->tokens = $tokens;
  }

  public function jsonSerialize(): mixed
  {
    return [
      "vault_id" => $this->vaultID,
      "tokens" => $this->tokens
    ];
  }
}

class VaultFetchInput implements JsonSerializable
{
  public string $vaultID;
  public mixed $search;
  public int $size;
  public string $after;

  public function __construct(string $vaultID, mixed $search, int $size, string $after)
  {
    $this->vaultID = $vaultID;
    $this->search = $search;
    $this->size = $size;
    $this->after = $after;
  }

  public function jsonSerialize(): mixed
  {
    return [
      "vault_id" => $this->vaultID,
      "search" => $this->search,
      "size" => $this->size,
      "after" => $this->after
    ];
  }
}

class VaultGetInput implements JsonSerializable
{
  public string $vaultID;
  public array $tokens;

  /**
   * @param array<string> $tokens
   */
  public function __construct(string $vaultID, array $tokens)
  {
    $this->vaultID = $vaultID;
    $this->tokens = $tokens;
  }

  public function jsonSerialize(): mixed
  {
    return [
      "vault_id" => $this->vaultID,
      "tokens" => $this->tokens
    ];
  }
}

class VaultUpdateInput implements JsonSerializable
{
  public string $vaultID;
  public array $values;

  /**
   * @param array<VaultUpdateInputValues> $values
   */
  public function __construct(string $vaultID, array $values)
  {
    $this->vaultID = $vaultID;
    $this->values = $values;
  }

  public function jsonSerialize(): mixed
  {
    return [
      "vault_id" => $this->vaultID,
      "values" => $this->values
    ];
  }
}

class VaultUpdateInputValues implements JsonSerializable
{
  public string $token;
  public mixed $value;

  public function __construct(string $token, mixed $value)
  {
    $this->token = $token;
    $this->value = $value;
  }

  public function jsonSerialize(): mixed
  {
    return [
      "token" => $this->token,
      "value" => $this->value
    ];
  }
}

class ProtectionSealInput implements JsonSerializable
{
  private string $protectionID;
  private array $primaryKeys;

  /**
   * @param array<mixed> $primaryKeys
   */
  public function __construct(string $protectionID, array $primaryKeys)
  {
    $this->protectionID = $protectionID;
    $this->primaryKeys = $primaryKeys;
  }

  public function jsonSerialize(): mixed
  {
    return [
      "protection_id" => $this->protectionID,
      "primary_keys" => $this->primaryKeys
    ];
  }
}

class ProtectionOpenInput implements JsonSerializable
{
  private string $protectionID;
  private array $tokens;

  /**
   * @param array<mixed> $tokens
   */
  public function __construct(string $protectionID, array $tokens)
  {
    $this->protectionID = $protectionID;
    $this->tokens = $tokens;
  }

  public function jsonSerialize(): mixed
  {
    return [
      "protection_id" => $this->protectionID,
      "tokens" => $this->tokens
    ];
  }
}

enum EncryptionMode: string
{
  case AES_GCM = "AES_GCM";
  case CHACHA20_POLY1305 = "CHACHA20_POLY1305";
  case XCHACHA20_POLY1305 = "XCHACHA20_POLY1305";
}

class CryptoEncryptInput implements JsonSerializable
{
  private string $keyID;
  private EncryptionMode $mode;
  private array $plaintexts;

  public function __construct(string $keyID, EncryptionMode $mode, array $plaintexts)
  {
    $this->keyID = $keyID;
    $this->mode = $mode;
    $this->plaintexts = $plaintexts;
  }

  public function jsonSerialize(): mixed
  {
    return [
      "key_id" => $this->keyID,
      "mode" => $this->mode,
      "plaintexts" => $this->plaintexts
    ];
  }
}

class CryptoEqualInput implements JsonSerializable
{
  private string $hash;
  private mixed $value;

  public function __construct(string $hash, mixed $value)
  {
    $this->hash = $hash;
    $this->value = $value;
  }

  public function jsonSerialize(): mixed
  {
    return [
      "hash" => $this->hash,
      "value" => $this->value
    ];
  }
}

class CryptoSignInput implements JsonSerializable
{
  private string $keyID;
  private array $values;

  public function __construct(string $keyID, array $values)
  {
    $this->keyID = $keyID;
    $this->values = $values;
  }

  public function jsonSerialize(): mixed
  {
    return [
      "key_id" => $this->keyID,
      "values" => $this->values
    ];
  }
}

class CryptoVerifyInput implements JsonSerializable
{
  private string $signature;
  private mixed $value;

  public function __construct(string $signature, mixed $value)
  {
    $this->signature = $signature;
    $this->value = $value;
  }

  public function jsonSerialize(): mixed
  {
    return [
      "signature" => $this->signature,
      "value" => $this->value
    ];
  }
}

enum HashMode: string
{
  case BLAKE2B_256 = "BLAKE2B_256";
  case BLAKE2B_512 = "BLAKE2B_512";
  case BLAKE2S_256 = "BLAKE2S_256";
  case BLAKE3_256 = "BLAKE3_256";
  case SHA256 = "SHA256";
  case SHA512 = "SHA512";
  case SHA3_256 = "SHA3_256";
  case SHA3_512 = "SHA3_512";
}

class CryptoHMACInput implements JsonSerializable
{
  private string $keyID;
  private HashMode $mode;
  private array $values;

  public function __construct(string $keyID, HashMode $mode, array $values)
  {
    $this->keyID = $keyID;
    $this->mode = $mode;
    $this->values = $values;
  }

  public function jsonSerialize(): mixed
  {
    return [
      "key_id" => $this->keyID,
      "mode" => $this->mode,
      "values" => $this->values
    ];
  }
}
