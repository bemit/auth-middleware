<?php declare(strict_types=1);

namespace Bemit\AuthMiddleware\ValidateResult;

class ProjectData {
    /**
     * @var string[]|null
     */
    protected ?array $projects = null;
    protected ?string $project = null;
    protected ?\stdClass $roles = null;
    /**
     * Further data associated with the token in the `projects` namespace
     * @var array|null
     */
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
            if($data['roles'] instanceof \stdClass) {
                $this->roles = $data['roles'];
            } else {
                $this->roles = new \stdClass();
                foreach($data['roles'] as $r => $role) {
                    $this->roles->$r = $role;
                }
            }
            unset($data['roles']);
        }
        $this->data = $data;
    }

    /**
     * @return string[]|null
     */
    public function getProjects(): ?array {
        return $this->projects;
    }

    public function getProject(): ?string {
        return $this->project;
    }

    public function getRoles(): ?\stdClass {
        return $this->roles;
    }

    public function getData(): ?array {
        return $this->data;
    }
}
