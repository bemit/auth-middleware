<?php declare(strict_types=1);

namespace Bemit\AuthMiddleware\ValidateResult;

class UserData {
    protected ?string $email = null;
    /**
     * Further data associated with the token in the `userdata` namespace
     * @var array|null
     */
    protected ?array $data = null;

    public function __construct(array $data) {
        if(isset($data['email'])) {
            $this->email = $data['email'];
            unset($data['email']);
        }
        $this->data = $data;
    }

    public function getEmail(): ?string {
        return $this->email;
    }

    public function getData(): ?array {
        return $this->data;
    }
}
