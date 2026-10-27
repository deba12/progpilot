<?php

/*
 * This file is part of ProgPilot, a static analyzer for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


namespace progpilot\Inputs;

use stdClass;

class MySanitizer extends MySpecify
{
    /**
     * @var list<string>
     */
    private array $prevent;
    /**
     * @var array<mixed>
     */
    private array $parameters;
    private bool $hasParameters;

    /**
     * @param list<string> $prevent
     */
    public function __construct(string $name, string $language, array $prevent)
    {
        parent::__construct($name, $language);

        $this->prevent = $prevent;
        $this->hasParameters = false;
        $this->parameters = [];
    }

    /**
     * @return list<string>
     */
    public function getPrevent(): array
    {
        return $this->prevent;
    }

    /**
     * @param list<stdClass>|null $values
     */
    public function addParameter(int $parameter, string $conditions, ?array $values = null): void
    {
        $this->parameters[] = [$parameter, $conditions, $values];
    }

    /**
     * @return array<mixed>
     */
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
            $conditions = $parameter[1];
            $values = $parameter[2];

            if ($index === $i) {
                return $values;
            }
        }

        return null;
    }

    public function isParameter(int $i): bool
    {
        foreach ($this->parameters as $parameter) {
            $index = $parameter[0];
            $conditions = $parameter[1];

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
