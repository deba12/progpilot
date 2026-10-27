<?php

/*
 * This file is part of ProgPilot, a static analyzer for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


namespace progpilot\Inputs;

use stdClass;

class MyValidator extends MySpecify
{
    private array $parameters;
    private bool $hasParameters;
    private bool $validWhenReturning;

    public function __construct($name, $language, $validWhenReturning)
    {
        parent::__construct($name, $language);

        $this->hasParameters = false;
        $this->parameters = [];
        $this->validWhenReturning = $validWhenReturning;
    }

    public function getValidWhenReturning(): bool
    {
        return $this->validWhenReturning;
    }

    public function setValidWhenReturning(bool $validWhenReturning, bool $validwhenreturning, $notboolean): void
    {
        $this->validWhenReturning = $validWhenReturning;
    }

    /**
     * @param list<stdClass>|null $values
     */
    public function addParameter(int $parameter, string $conditions, ?array $values = null): void
    {
        $this->parameters[] = [$parameter, $conditions, $values];
    }

    public function getParameters(): array
    {
        return $this->parameters;
    }

    public function getParameterconditions(int $i): ?string
    {
        foreach ($this->parameters as $parameter) {
            $index = $parameter[0];
            $conditions = $parameter[1];

            if ($index === $i) {
                return $conditions;
            }
        }

        return null;
    }

    /**
     * @return list<stdClass>|null
     */
    public function getParameterValues(int $i): ?array
    {
        foreach ($this->parameters as $parameter) {
            $index = $parameter[0];
            $values = $parameter[2];

            if ($index === $i) {
                return $values;
            }
        }

        return null;
    }

    public function isParameter($i): bool
    {
        foreach ($this->parameters as $parameter) {
            $index = $parameter[0];

            if ($index === $i) {
                return true;
            }
        }

        return false;
    }

    public function hasParameters(): bool
    {
        return $this->hasParameters;
    }

    public function setHasParameters(bool $hasParameters): void
    {
        $this->hasParameters = $hasParameters;
    }
}
