# Kastela SDK for PHP

## Related Link

- [API docs](https://kastela-sdp.github.io/kastela-sdk-php/)
- [Packagist link](https://packagist.org/packages/kastela-sdp/kastela-sdk-php)

## Usage Example

Credential is required when using the SDK, download it on the entities page.

```php
$kastelaClient = new Client("server.url", "ca/path.crt", "client/credential/path.crt", "client/credential/path.key", );
// decrypt data with id 1,2,3,4,5
$data = kastelaClient->protection_open(new ProtectionOpenInput("id", ["token1", "token2"])]);
```
