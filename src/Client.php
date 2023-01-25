<?php

/**
 * Summary
 */
namespace Kastela;

use Error;

define("expectedKastelaVersion", "v0.2");
define("protectionPath", "/api/protection/");
define("vaultPath", "/api/vault/");
define("privacyProxyPath", "/api/proxy");

/**
 * Create a new Kastela Client instance for communicating with the server.
 * Require server information and return client instance.
 * ##### Example
 * ```php
 * $kastelaClient = new Client("server.url", "ca/path.crt", "client/credential/path.crt", "client/credential/path.key", );
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
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $reqBody);
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

    $headers = [];
    foreach (explode("\r\n", $header) as $i => $line)
      if ($i === 0)
        $headers['http_code'] = $line;
      else {
        list($key, $value) = explode(': ', $line);

        $headers[$key] = $value;
      }
    $splitCurrentV = explode('.', $headers['X-Kastela-Version']);
    $currentVersion = $splitCurrentV[0] . '.' . $splitCurrentV[1];
    if (version_compare($currentVersion, expectedKastelaVersion) != 0) {
      throw new \Error("kastela server version mismatch, expected: " . expectedKastelaVersion . ".x, actual: " . $headers['X-Kastela-Version']);
    }

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

  /** Encrypt data protection by protection data ids, which can be used after storing data or updating data.
   * @param string $protectionId
   * @param mixed[] $ids array of protection data ids
   * @return void
   * ##### Example
   * ```php
   * // protect data with id 1,2,3,4,5
   * kastelaClient->protection_seal("5f77f9c2-2800-4661-b479-a0791aa0eacc", [1,2,3,4,5]);
   * ```
   */
  public function protectionSeal($protectionId, $ids)
  {
    $url = $this->kastelaUrl . protectionPath . $protectionId . '/seal';
    $body = ["ids" => $ids];

    $this->request('post', $url, $body);
  }

  /** Decrypt data protection by protection data ids.
   * @param string $protectionId
   * @param mixed[] $ids array of protection data ids
   * @return mixed[] $array of decrypted data refers to ids
   * ##### Example
   * ```php
   * // decrypt data with id 1,2,3,4,5
   * $emails = kastelaClient->protection_open("5f77f9c2-2800-4661-b479-a0791aa0eacc", [1,2,3,4,5]); // return plain email
   * ```
   */
  public function protectionOpen($protectionId, $ids)
  {
    $url = $this->kastelaUrl . protectionPath . $protectionId . '/open';
    $body = ["ids" => $ids];

    $res = $this->request('post', $url, $body);
    return $res["data"];
  }

  /** Store batch vault data on the server.
   * @param string $vaultId
   * @param mixed[] $data array of vault data
   * @return string[] array of vault token
   * ##### Example
   * ```php
   * $secret = $kastelaClient->vault_store("20e25596-db90-4945-ae0b-5886ba1bfdd0", [["name" => $request->name, "secret" => $request->secret]])
   * ```
   */
  public function vaultStore($vaultId, $data)
  {
    $url = $this->kastelaUrl . vaultPath . $vaultId . '/store';
    $body = ["data" => $data];

    $res = $this->request('post', $url, $body);
    return $res["ids"];
  }

  /** Search vault data by indexed column.
   * @param string $vaultId
   * @param string $search indexed column value
   * @param array $params pagination parameters.
   * $params = [
   *    'size' => (int) pagination size.,
   *    'after' => (string) pagination offset
   * ]
   * @return string[]
   * ##### Example
   * ```php
   * // fetch vault data with indexed colum value "jhon doe", return the list of vault token/id
   * $ids = $kastelaClient->vault_fetch("20e25596-db90-4945-ae0b-5886ba1bfdd0", "jhon doe", []);
   * ```
   */
  public function vaultFetch($vaultId, $search, $params)
  {
    $baseUrl = $this->kastelaUrl . vaultPath . $vaultId;

    $params = ["search" => $search];
    if (isset($params["size"])) {
      array_push($params, ["size" => $params["size"]]);
    }
    if (isset($params["affter"])) {
      array_push($params, ["after" => $params["after"]]);
    }

    $url = $baseUrl . '?' . http_build_query($params);

    $res = $this->request('get', $url, null);
    return $res["ids"];
  }

  /** Get batch vault data by vault token ids.
   * @param string $vaultId
   * @param string[] $ids array of vault token
   * @return mixed[]
   * ##### Example
   * ```php
   * // get vault data
   *  $secrets = $kastelaClient->vault_get("20e25596-db90-4945-ae0b-5886ba1bfdd0", ["d2657324-59f3-4bd4-92b0-c7f5e5ef7269", "331787a5-8930-4167-828f-7e783aeb158c"]);
   * ```
   */
  public function vaultGet($vaultId, $ids)
  {
    $url = $this->kastelaUrl . vaultPath . $vaultId . '/get';
    $body = ["ids" => $ids];

    $res = $this->request('post', $url, $body);
    return $res["data"];
  }

  /** Update vault data by vault token.
   * @param string $vaultId
   * @param string[] $token vault token
   * @param mixed $data update data
   * @return void
   * ##### Example
   * ```php
   * $kastelaClient->vault_update("20e25596-db90-4945-ae0b-5886ba1bfdd0", "331787a5-8930-4167-828f-7e783aeb158c", ["name" => "jane d'arc", "secret" => "this is new secret"]);
   * ```
   */
  public function vaultUpdate($vaultId, $token, $data)
  {
    $url = $this->kastelaUrl . vaultPath . $vaultId . '/' . $token;
    $this->request('put', $url, $data);
  }

  /** Remove vault data by vault token.
   * @param string $vaultId
   * @param string $token vault token
   * @return void
   * ##### Example
   * ```php
   * $kastelaClient->vault_delete("20e25596-db90-4945-ae0b-5886ba1bfdd0", "331787a5-8930-4167-828f-7e783aeb158c");
   * ```
   */
  public function vaultDelete($vaultId, $token)
  {
    $url = $this->kastelaUrl . vaultPath . $vaultId . '/' . $token;
    $this->request('delete', $url, null);
  }

  /** Proxying Request.
   * @param string $type request body type "json"|"xml"
   * @param string $url request url
   * @param string $method request method "get"|"post"
   * @param array $common needed information for protection and vault.
   * $common = [
   *    'protections' => ['_column'=>'protectionId'] protections object list. Define column with prefix as key and protectionId as value.
   *    'vaults' => ['_column'=>['vaultId', 'selectedVaultColumn']]] vaults object list. Define column with prefix as key and array with id as first index and vault column as second index.
   * ]
   * @param array $options
   * $options = [
   *    'headers' => (array) {object} request headers, use "_" prefix for encrypted column key and data id/token as value.
   *    'params' => (array) {object} request parameters, use "_" prefix for encrypted column key and data id/token as value.
   *    'body' => (array) {object} request body, use "_" prefix for encrypted column key and data id/token as value.
   *    'query' => (array)  {object} request query, use "_" prefix for encrypted column key and data id/token as value.
   *    'rootTag' => (string) root tag, required for xml type
   * ]
   */
  public function privacyProxyRequest(string $type, string $url, string $method, array $common, array $options)
  {
    if ($type === "xml") {
      throw new \Error("rootTag is required for xml");
    }
    $kastelUrl = $this->kastelaUrl.privacyProxyPath;
    $res = $this->request('post', $kastelUrl, [
      "type" => $type,
      "url" => $url,
      "method" => $method,
      "common" => $common,
      "options" => $options
    ]);
    return $res;
  }
}
;