<?php declare(strict_types=1);

namespace Bemit\AuthMiddleware;

use Auth0\SDK\Auth0;
use Auth0\SDK\Configuration\SdkConfiguration;
use Auth0\SDK\Contract\API\ManagementInterface;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Log\LoggerInterface;

class Auth0Service {
    protected string $issuer;
    protected string $client_id;
    protected string $client_secret;

    private ?string $backend_token = null;

    private ClientInterface $http_client;

    private LoggerInterface $logger;

    public function __construct(
        string          $issuer, string $client_id, string $client_secret,
        ClientInterface $http_client, LoggerInterface $logger,
    ) {
        $this->issuer = $issuer;
        $this->client_id = $client_id;
        $this->client_secret = $client_secret;
        $this->http_client = $http_client;
        $this->logger = $logger;
    }

    protected function authBackend(): void {
        try {
            $auth_resp = $this->http_client->request('POST', $this->issuer . 'oauth/token', [
                'json' => [
                    'client_id' => $this->client_id,
                    'client_secret' => $this->client_secret,
                    'audience' => $this->issuer . 'api/v2/',
                    'grant_type' => 'client_credentials',
                ],
            ]);
            $resp = json_decode($auth_resp->getBody()->getContents(), false, 512, JSON_THROW_ON_ERROR);
            if(property_exists($resp, 'access_token')) {
                $this->backend_token = $resp->access_token;
            }
        } catch(ClientExceptionInterface $e) {
            $this->logger->error($e->getMessage(), (array)$e);
        }
        if(!$this->backend_token) {
            throw new \RuntimeException('backend not validated');
        }
    }

    public function management(): ManagementInterface {
        // The process for retrieving an Access Token for Management API endpoints is described here:
        // https://auth0.com/docs/libraries/auth0-php/using-the-management-api-with-auth0-php
        if(!$this->backend_token) {
            $this->authBackend();
        }
        $configuration = new SdkConfiguration(
            domain: $this->issuer,
            clientId: $this->client_id,
            clientSecret: $this->client_secret,
            managementToken: $this->backend_token,
        );

        return (new Auth0($configuration))->management();
    }
}
