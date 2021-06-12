<?php declare(strict_types=1);

namespace Bemit\AuthMiddleware\ValidateResult;

class ProjectsData {
    protected ?array $projects = null;
    protected ?string $project = null;
    protected $roles = null;
    protected ?array $data = null;

    public function __construct(array $data) {
        if(isset($data['projects'])) {
            $this->projects = $data['projects'];
            unset($data['projects']);
        }
        if(isset($data['project'])) {
            $this->project = $data['project'];
            unset($data['project']);
        }
        if(isset($data['roles'])) {
            $this->roles = $data['roles'];
            unset($data['roles']);
        }
        $this->data = $data;
    }

    public function getProjects(): ?array {
        return $this->projects;
    }

    public function getProject(): ?string {
        return $this->project;
    }

    public function getRoles() {
        return $this->roles;
    }
}
