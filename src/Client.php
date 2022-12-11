<?php

namespace Kastela;

define("expectedKastelaVersion", "v0.0");
define("protectionPath", "/api/protection/");
define("vaultPath", "/api/vault/");

class Client
{
  public $kastelaUrl;
  private $ch;

  public function __construct($kastelaUrl, $caCertPath, $clientCertPath, $clientKeyPath)
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

  public function protection_seal($protectionId, $ids)
  {
    $url = $this->kastelaUrl . protectionPath . $protectionId . '/seal';
    $body = ["ids" => $ids];

    $this->request('post', $url, $body);
  }
  public function protection_open($protectionId, $ids)
  {
    $url = $this->kastelaUrl . protectionPath . $protectionId . '/open';
    $body = ["ids" => $ids];

    $res = $this->request('post', $url, $body);
    return $res["data"];
  }

  public function vault_store($vaultId, $data)
  {
    $url = $this->kastelaUrl . vaultPath . $vaultId . '/store';
    $body = ["data" => $data];

    $res = $this->request('post', $url, $body);
    return $res["ids"];
  }
  public function vault_fetch($vaultId, $search, $params)
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
  public function vault_get($vaultId, $ids)
  {
    $url = $this->kastelaUrl . vaultPath . $vaultId . '/get';
    $body = ["ids" => $ids];

    $res = $this->request('post', $url, $body);
    return $res["data"];
  }
  public function vault_update($vaultId, $token, $data)
  {
    $url = $this->kastelaUrl . vaultPath . $vaultId . '/' . $token;
    $this->request('put', $url, $data);
  }
  public function vault_delete($vaultId, $token)
  {
    $url = $this->kastelaUrl . vaultPath . $vaultId . '/' . $token;
    $this->request('delete', $url, null);
  }
};
