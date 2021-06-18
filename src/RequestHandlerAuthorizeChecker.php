<?php declare(strict_types=1);

namespace Bemit\AuthMiddleware;

use Psr\Http\Message\ServerRequestInterface;

trait RequestHandlerAuthorizeChecker {

    public function requireRole(ServerRequestInterface $request, string $service, string $role): void {
        $project = RequestAuthorizeContext::getProject($request);
        if(!$project) {
            throw new NotAuthorizedException('no roles granted');
        }
        $roles = $project->getRoles();
        if(
            !$roles ||
            !property_exists($roles, $service) ||
            !is_array($roles->$service) ||
            !in_array($role, $roles->$service, true)
        ) {
            throw new NotAuthorizedException('role `' . $role . '` is not granted for service `' . $service . '`');
        }
    }

    public function requireRoleOneOf(ServerRequestInterface $request, string $service, array $possible_roles): void {
        $project = RequestAuthorizeContext::getProject($request);
        if(!$project) {
            throw new NotAuthorizedException('no roles granted');
        }
        $roles = $project->getRoles();
        $found = false;
        if(
            $roles &&
            property_exists($roles, $service) &&
            is_array($roles->$service)
        ) {
            foreach($possible_roles as $possible_role) {
                if(in_array($possible_role, $roles->$service, true)) {
                    $found = true;
                    break;
                }
            }
        }

        if(!$found) {
            throw new NotAuthorizedException('no roles granted for service `' . $service . '` would need one of `' . implode(', ', $possible_roles) . '`');
        }
    }

    public function requireProjectAccess(ServerRequestInterface $request, string $project_id): void {
        $project = RequestAuthorizeContext::getProject($request);
        if(!$project || $project->getProject() !== $project_id) {
            if(
                $project &&
                is_array($project->getProjects()) &&
                in_array($project_id, $project->getProjects(), true)
            ) {
                throw new NotAuthorizedException('access to project ' . $project_id . ' not allowed with current token');
            }
            throw new NotAuthorizedException('access to project ' . $project_id . ' is not allowed');
        }
    }
}
