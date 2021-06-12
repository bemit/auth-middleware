<?php declare(strict_types=1);

namespace Bemit\AuthMiddleware;

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

class AuthMiddleware implements MiddlewareInterface {
    protected $auth;
    protected ResponseFactoryInterface $response;
    protected StreamFactoryInterface $stream;

    public function __construct(AuthService $auth, ResponseFactoryInterface $response, StreamFactoryInterface $stream) {
        $this->auth = $auth;
        $this->response = $response;
        $this->stream = $stream;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface {
        $audience = '';
        if(isset($_SERVER['HTTP_AUDIENCE']) && trim($_SERVER['HTTP_AUDIENCE']) !== '') {
            $audience = trim($_SERVER['HTTP_AUDIENCE']);
            if(!$this->auth->isAudienceAllowed($audience)) {
                return $this->response->createResponse(401)
                    ->withBody($this->stream->createStream(json_encode([
                        'result' => null,
                        'error' => 'not authenticated',
                        'reason' => 'requested audience is not allowed in service',
                    ], JSON_THROW_ON_ERROR)))
                    ->withHeader('Content-Type', 'application/json');
            }
        }
        if(
            isset($_SERVER['HTTP_AUTHORIZATION']) &&
            strlen($_SERVER['HTTP_AUTHORIZATION']) > strlen('Bearer ') &&
            trim(substr($_SERVER['HTTP_AUTHORIZATION'], strlen('Bearer '))) !== ''
        ) {
            $validate_result = $this->auth->validate(substr($_SERVER['HTTP_AUTHORIZATION'], strlen('Bearer ')), $audience);
            if($validate_result) {
                $request = $request
                    ->withAttribute('auth_token_data', $validate_result->getTokenData())
                    ->withAttribute('auth_user_data', $validate_result->getUserData())
                    ->withAttribute('auth_project', $validate_result->getProject())
                    ->withAttribute('auth_id', $validate_result->getTokenData()->getUserId());
            }
        }
        try {
            $response = $handler->handle($request);
        } catch(NotAuthorizedException $e) {
            return $this->response->createResponse(401)
                ->withBody($this->stream->createStream(json_encode([
                    'result' => null,
                    'error' => 'not authorized',
                    'reason' => $e->getMessage(),
                ], JSON_THROW_ON_ERROR)))
                ->withHeader('Content-Type', 'application/json');
        }

        return $response;
    }
}
