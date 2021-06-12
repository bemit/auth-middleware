<?php declare(strict_types=1);

namespace Bemit\AuthMiddleware\ValidateResult;

class ValidateResult {
    protected TokenData $token_data;
    protected UserData $user_data;
    protected ProjectsData $project_data;

    public function __construct(TokenData $token_data, UserData $user_data, ProjectsData $project_data) {
        $this->token_data = $token_data;
        $this->user_data = $user_data;
        $this->project_data = $project_data;
    }

    public function getTokenData(): TokenData {
        return $this->token_data;
    }

    public function getUserData(): UserData {
        return $this->user_data;
    }

    public function getProject(): ProjectsData {
        return $this->project_data;
    }
}
