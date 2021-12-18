<?php declare(strict_types=1);

namespace Bemit\AuthMiddleware\ValidateResult;

class TokenData {
    /**
     * @var string[]|null
     */
    protected ?array $scope = null;
    protected ?string $sub = null;
    /**
     * @var string[]|null
     */
    protected ?array $permissions = null;
    /**
     * Further data associated with the token
     * @var array|null
     */
    protected ?array $data = null;

    public function __construct(array $data) {
        if(isset($data['sub'])) {
            $this->sub = $data['sub'];
            unset($data['sub']);
        }
        if(isset($data['scope'])) {
            $this->scope = $data['scope'];
            unset($data['scope']);
        }
        if(isset($data['permissions'])) {
            $this->permissions = $data['permissions'];
            unset($data['permissions']);
        }
        $this->data = $data;
    }

    public function getScopes(): ?array {
        return $this->scope;
    }

    public function getUserId(): ?string {
        return $this->sub;
    }

    public function getPermissions(): ?array {
        return $this->permissions;
    }

    public function getData(): ?array {
        return $this->data;
    }
}
