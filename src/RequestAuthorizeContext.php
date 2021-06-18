<?php declare(strict_types=1);

namespace Bemit\AuthMiddleware;

use Bemit\AuthMiddleware\ValidateResult\ProjectData;
use Bemit\AuthMiddleware\ValidateResult\TokenData;
use Bemit\AuthMiddleware\ValidateResult\UserData;
use Psr\Http\Message\ServerRequestInterface;

class RequestAuthorizeContext {
    public static function getTokenData(ServerRequestInterface $request): ?TokenData {
        return $request->getAttribute(AuthMiddleware::$request_attribute__token_data);
    }

    public static function getUserData(ServerRequestInterface $request): ?UserData {
        return $request->getAttribute(AuthMiddleware::$request_attribute__user_data);
    }

    public static function getProject(ServerRequestInterface $request): ?ProjectData {
        return $request->getAttribute(AuthMiddleware::$request_attribute__project);
    }

    public static function getId(ServerRequestInterface $request): ?string {
        return $request->getAttribute(AuthMiddleware::$request_attribute__id);
    }
}
