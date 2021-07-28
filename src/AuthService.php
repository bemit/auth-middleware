<?php declare(strict_types=1);

namespace Bemit\AuthMiddleware;

use Auth0\SDK\Exception\InvalidTokenException;
use Auth0\SDK\Helpers\JWKFetcher;
use Auth0\SDK\Helpers\Tokens\AsymmetricVerifier;
use Auth0\SDK\Helpers\Tokens\TokenVerifier;
use Bemit\AuthMiddleware\ValidateResult\ProjectData;
use Bemit\AuthMiddleware\ValidateResult\TokenData;
use Bemit\AuthMiddleware\ValidateResult\UserData;
use Bemit\AuthMiddleware\ValidateResult\ValidateResult;
use Psr\SimpleCache\CacheInterface;

class AuthService {
    protected string $issuer;
    protected string $default_audience;
    protected string $namespace_user_data;
    protected string $namespace_projects;
    protected array $allowed_audiences;
    protected ?CacheInterface $cache = null;

    /**
     * @param string $issuer
     * @param string $audience
     * @param string $namespace_user_data
     * @param string $namespace_projects
     * @param array $allowed_audiences
     * @param CacheInterface|null $cache
     */
    public function __construct(
        string $issuer, string $audience,
        string $namespace_user_data, string $namespace_projects,
        array $allowed_audiences,
        ?CacheInterface $cache = null
    ) {
        $this->issuer = $issuer;
        $this->default_audience = $audience;
        $this->namespace_user_data = $namespace_user_data;
        $this->namespace_projects = $namespace_projects;
        $this->allowed_audiences = $allowed_audiences;
        $this->cache = $cache;
    }

    protected function getJwk() {
        $jwks_fetcher = new JWKFetcher($this->cache);
        $jwks = $jwks_fetcher->getKeys($this->issuer . '.well-known/jwks.json');
        return $jwks;
    }

    /**
     * @param string $token
     * @param string|null $audience
     * @return ValidateResult|null
     */
    public function validate(string $token, ?string $audience = null): ?ValidateResult {
        $jwks = $this->getJwk();
        $sigVerifier = new AsymmetricVerifier($jwks);
        $tokenVerifier = new TokenVerifier($this->issuer, $audience ?? $this->default_audience, $sigVerifier);
        $token_data = [];
        $user_data = [];
        $projects = [];

        try {
            $tokenInfo = $tokenVerifier->verify($token);
            if(is_array($tokenInfo)) {
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
            return null;
        }
        return new ValidateResult(new TokenData($token_data), new UserData($user_data), new ProjectData($projects));
    }

    public function isAudienceAllowed(string $audience): bool {
        return in_array($audience, $this->allowed_audiences, true);
    }
}
