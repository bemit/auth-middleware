<?php declare(strict_types=1);

namespace Bemit\AuthMiddleware;

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

class AuthMiddleware implements MiddlewareInterface {
    public static $request_attribute__token_data = 'auth_token_data';
    public static $request_attribute__user_data = 'auth_user_data';
    public static $request_attribute__project = 'auth_project';
    public static $request_attribute__id = 'auth_id';

    protected $auth;
    protected ResponseFactoryInterface $response;
    protected StreamFactoryInterface $stream;

    public function __construct(AuthService $auth, ResponseFactoryInterface $response, StreamFactoryInterface $stream) {
        $this->auth = $auth;
        $this->response = $response;
        $this->stream = $stream;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface {
        $audience = $this->getRequestAudience($request->getServerParams());
        if($audience && !$this->auth->isAudienceAllowed($audience)) {
            return $this->response->createResponse(401)
                ->withBody($this->stream->createStream(json_encode([
                    'error' => 'not authenticated',
                    'reason' => 'requested audience is not allowed in service',
                ], JSON_THROW_ON_ERROR)))
                ->withHeader('Content-Type', 'application/json');
        }

        $request = $this->maybeValidateToken($request, $audience);

        try {
            $response = $handler->handle($request);
        } catch(NotAuthorizedException $e) {
            return $this->response->createResponse(401)
                ->withBody($this->stream->createStream(json_encode([
                    'error' => 'not authorized',
                    'reason' => $e->getMessage(),
                ], JSON_THROW_ON_ERROR)))
                ->withHeader('Content-Type', 'application/json');
        }

        return $response;
    }

    protected function getRequestAudience(array $server_params): ?string {
        $audience = null;
        if(isset($server_params['HTTP_AUDIENCE']) && trim($server_params['HTTP_AUDIENCE']) !== '') {
            $audience = trim($server_params['HTTP_AUDIENCE']);
        }
        return $audience;
    }

    protected function maybeValidateToken(ServerRequestInterface $request, ?string $audience = null): ServerRequestInterface {
        $server_params = $request->getServerParams();
        $bearer_prefix_length = strlen('Bearer ');
        if(
            isset($server_params['HTTP_AUTHORIZATION']) &&
            strlen($server_params['HTTP_AUTHORIZATION']) > $bearer_prefix_length &&
            trim(substr($server_params['HTTP_AUTHORIZATION'], $bearer_prefix_length)) !== ''
        ) {
            $validate_result = $this->auth->validate(substr($server_params['HTTP_AUTHORIZATION'], $bearer_prefix_length), $audience);
            if($validate_result) {
                $request = $request
                    ->withAttribute(self::$request_attribute__token_data, $validate_result->getTokenData())
                    ->withAttribute(self::$request_attribute__user_data, $validate_result->getUserData())
                    ->withAttribute(self::$request_attribute__project, $validate_result->getProject())
                    ->withAttribute(self::$request_attribute__id, $validate_result->getTokenData()->getUserId());
            }
        }
        return $request;
    }
}
