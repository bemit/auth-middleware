# Auth0 Service and Middleware

[![Latest Stable Version](http://poser.pugx.org/bemit/auth-middleware/v)](https://packagist.org/packages/bemit/auth-middleware) [![License](http://poser.pugx.org/bemit/auth-middleware/license)](https://packagist.org/packages/bemit/auth-middleware)

Some custom auth middleware to support multi tenants (a tenant is a `project` then) and multiple "providing services" against which a user in a project is identified and maybe authorized. Build with / around [auth0](https://auth0.com) and some (not published) custom identity provider.

Requires `psr/http-client`, `psr/http-factory` and `psr/log` implementations.

Made for stateless PHP APIs, not for PHP session auth. Uses one Auth0 SPA Application which produces/verifies the access token, and an optional Auth0 Server Application which is used to auth against the Auth0 Management API.

```shell
composer require bemit/auth-middleware
```

## `Bemit\AuthMiddleware\Auth0Service`

Provides the Auth0 management API client, if not used, doesn't need to be configured.

- for constructor check [example dependencies definition](#dependencies)
- `management(): Management`

## `Bemit\AuthMiddleware\AuthService`

Provides the verifier for client access tokens.

- for constructor check [example dependencies definition](#dependencies)
- `validate(string $token, ?string $audience = null): ?ValidateResult` to verify a token
    - the token must be pure, e.g. without `Bearer `
    - if `audience` is specified, this audience is used to verify the token, it must be in `allowed_audiences`
- `isAudienceAllowed(string $audience): bool`

## `Bemit\AuthMiddleware\AuthMiddleware`

A PSR Middleware that extracts the access token and maybe an audience from headers, verifies it and adds the validation result to the request attributes.

If e.g. the audience is not allowed, returns `401` with a JSON response containing the reason. **No special handling** when the token is invalid, check inside your request handler and throw/response accordingly. **Catches throws** of `NotAuthorizedException` and responds with `401`, with `{error: string, reason: string}`, where `reason` is the optional exception message.

- `__construct(AuthService $auth, Psr\Http\Message\ResponseFactoryInterface $response, Psr\Http\Message\StreamFactoryInterface $stream)`
- `process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface`

Uses headers:

- `AUDIENCE` to optionally specify a custom audience id
- `AUTHORIZATION` the access token in `Bearer THE_TOKEN_A1234` format

Adding attributes when authenticated:

- `auth_token_data` as [`Bemit\AuthMiddleware\TokenData`](https://github.com/bemit/auth-middleware/blob/master/src/ValidateResult/TokenData.php)
- `auth_user_data` as [`Bemit\AuthMiddleware\UserData`](https://github.com/bemit/auth-middleware/blob/master/src/ValidateResult/UserData.php)
- `auth_project` as [`Bemit\AuthMiddleware\ProjectData`](https://github.com/bemit/auth-middleware/blob/master/src/ValidateResult/ProjectsData.php)
- `auth_id` as `string` with the `sub` (user-id)

## `Bemit\AuthMiddleware\RequestHandlerAuthorizeChecker`

`trait` for PSR request handler to easily validate if access should be granted, throws `Bemit\AuthMiddleware\NotAuthorizedException` when some authorize check fails.

- `requireRole(ServerRequestInterface $request, string $service, string $role): void`
    - fails when role is not granted for the service
- `requireRoleOneOf(ServerRequestInterface $request, string $service, array $possible_roles): void`
    - `possible_roles` as `string[]`, only one of the specified roles must match
- `requireProjectAccess(ServerRequestInterface $request, string $project_id): void`
    - does not check for any roles, only that the specified access token is valid against the given `project`

## `Bemit\AuthMiddleware\RequestAuthorizeContext`

Convenience functions to get the typed data out of the server request attributes.

- `static getTokenData(ServerRequestInterface $request): ?TokenData`
- `static getUserData(ServerRequestInterface $request): ?UserData`
- `static getProject(ServerRequestInterface $request): ?ProjectData`
- `static getId(ServerRequestInterface $request): ?string`

## `Bemit\AuthMiddleware\NotAuthorizedException`

Exception to be used when needs authorization, but doesn't have them.

## Dependencies

Dependency definition example, with PHP\DI:

```php
<?php

use function DI\autowire;
use function DI\get;

$dependencies = [
    // the middleware uses `AuthService and psr/http-factory implementation for responses
    Bemit\AuthMiddleware\AuthMiddleware::class => autowire(),
    Bemit\AuthMiddleware\AuthService::class => autowire()
        ->constructorParameter('issuer', $_ENV['AUTH_CLIENT_ISSUER'])
        ->constructorParameter('audience', $_ENV['AUTH_CLIENT_AUDIENCE'])
        // use either frontend client id for e.g. APIs or otherwise same as for Auth0Service
        ->constructorParameter('client_id', $_ENV['AUTH0_CLIENT_ID_FRONTEND'])
        ->constructorParameter('namespace_user_data', 'https://userdata')
        ->constructorParameter('namespace_projects', 'https://id.namespace')
        ->constructorParameter('allowed_audiences', [
            $_ENV['AUTH_CLIENT_AUDIENCE'],
        ])
        // optional, for jwks caching:
        ->constructorParameter('cache', get(Psr\SimpleCache\CacheInterface::class)),
    Bemit\AuthMiddleware\Auth0Service::class => autowire()
        ->constructorParameter('issuer', $_ENV['AUTH_CLIENT_ISSUER'])
        ->constructorParameter('client_id', $_ENV['AUTH0_CLIENT_ID'])
        ->constructorParameter('client_secret', $_ENV['AUTH0_CLIENT_SECRET'])
        ->constructorParameter('http_client', get(Psr\Http\Client\ClientInterface::class))
        ->constructorParameter('logger', get(Psr\Log\LoggerInterface::class)),
];
```

## License

This project is free software distributed under the [**MIT License**](LICENSE).

### Contributors

By committing your code to the code repository you agree to release the code under the MIT License attached to the repository.

***

Maintained by [Michael Becker](https://mlbr.xyz)
