<?php declare(strict_types=1);

namespace Bemit\AuthMiddleware;

use Auth0\SDK\Exception\InvalidTokenException;
use Auth0\SDK\Token;
use Bemit\AuthMiddleware\ValidateResult\ProjectData;
use Bemit\AuthMiddleware\ValidateResult\TokenData;
use Bemit\AuthMiddleware\ValidateResult\UserData;
use Bemit\AuthMiddleware\ValidateResult\ValidateResult;
use Psr\Cache\CacheItemPoolInterface;

class AuthService {
    protected string $issuer;
    protected string $default_audience;
    protected string $client_id;
    protected string $namespace_user_data;
    protected string $namespace_projects;
    protected array $allowed_audiences;
    protected bool $debug_invalid_jwt;
    protected ?CacheItemPoolInterface $cache = null;
    protected ?int $cache_ttl = null;

    /**
     * @param string $issuer
     * @param string $audience
     * @param string $client_id
     * @param string $namespace_user_data
     * @param string $namespace_projects
     * @param array $allowed_audiences
     * @param CacheItemPoolInterface|null $cache
     * @param int|null $cache_ttl
     * @param bool $debug_invalid_jwt
     */
    public function __construct(
        string                  $issuer, string $audience,
        string                  $client_id,
        string                  $namespace_user_data, string $namespace_projects,
        array                   $allowed_audiences,
        ?CacheItemPoolInterface $cache = null,
        ?int                    $cache_ttl = null,
        bool                    $debug_invalid_jwt = false,
    ) {
        $this->issuer = $issuer;
        $this->default_audience = $audience;
        $this->client_id = $client_id;
        $this->namespace_user_data = $namespace_user_data;
        $this->namespace_projects = $namespace_projects;
        $this->allowed_audiences = $allowed_audiences;
        $this->cache = $cache;
        $this->cache_ttl = $cache_ttl;
        $this->debug_invalid_jwt = $debug_invalid_jwt;
    }


    public function client(string $audience) {
        return new \Auth0\SDK\Auth0([
            'domain' => $this->issuer,
            'clientId' => $this->client_id,
            //'clientSecret' => $this->client_secret,
            'audience' => $audience ? [$audience] : null,
            'tokenCache' => $this->cache,
            'tokenCacheTtl' => $this->cache_ttl,
        ]);
    }

    /**
     * @param string $token
     * @param string|null $audience
     * @return ValidateResult|null
     */
    public function validate(string $token, ?string $audience = null): ?ValidateResult {
        $token_data = [];
        $user_data = [];
        $projects = [];

        try {
            $tokenInfoRes = $this->client($audience)->decode(
                $token, null, null, null, null, null, null, Token::TYPE_TOKEN,
            );

            // todo: get rid of this re-conversion, needed for auth0 v8 compatibility
            $tokenInfo = json_decode(json_encode($tokenInfoRes->toArray(), JSON_THROW_ON_ERROR), false, 512, JSON_THROW_ON_ERROR);
            if($tokenInfo instanceof \stdClass) {
                $tokenInfo = get_object_vars($tokenInfo);
                foreach($tokenInfo as $key => $info) {
                    if(str_starts_with($key, $this->namespace_user_data . '/')) {
                        $user_data[substr($key, strlen($this->namespace_user_data . '/'))] = $info;
                    } else if(str_starts_with($key, $this->namespace_projects . '/')) {
                        $projects[substr($key, strlen($this->namespace_projects . '/'))] = $info;
                    } else if($key === 'scope') {
                        $token_data['scope'] = explode(' ', $info);
                    } else {
                        $token_data[$key] = $info;
                    }
                }
            }
        } catch(InvalidTokenException $e) {
            if($this->debug_invalid_jwt) {
                throw $e;
            }
            return null;
        }
        return new ValidateResult(new TokenData($token_data), new UserData($user_data), new ProjectData($projects));
    }

    public function isAudienceAllowed(string $audience): bool {
        return in_array($audience, $this->allowed_audiences, true);
    }
}
