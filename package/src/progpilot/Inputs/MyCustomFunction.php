<?php

/*
 * This file is part of ProgPilot, a static analyzer for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


namespace progpilot\Inputs;

use stdClass;

class MyCustomFunction extends MySpecify
{
    private array $parameters;
    private bool $hasParameters;

    private ?string $action = null;
    private int $orderNumberExpected;
    private int $orderNumberReal;

    private int $minNbArgs;
    private int $maxNbArgs;

    public function __construct($name, $language, $orderNumberExpected = 0)
    {
        parent::__construct($name, $language);
        $this->action = null;
        $this->orderNumberExpected = $orderNumberExpected;
        $this->orderNumberReal = -1;

        $this->minNbArgs = 0;
        $this->maxNbArgs = PHP_INT_MAX;

        $this->hasParameters = false;
        $this->parameters = [];
    }

    /**
     * @param list<stdClass>|null $values
     */
    public function addParameter(
        int $parameter,
        bool $validbydefault,
        bool $fixed,
        bool $sufficient,
        bool $failifnotverified,
        bool $notequals,
        ?array $values = null
    ): void {
        $this->parameters[] = [
            $parameter,
            $values,
            $validbydefault,
            $fixed,
            $sufficient,
            $failifnotverified,
            $notequals
        ];
    }

    /**
     * @return list<array<mixed>>
     */
    public function getParameters(): array
    {
        return $this->parameters;
    }

    public function hasParameters(): bool
    {
        return $this->hasParameters;
    }

    public function setHasParameters(bool $hasParameters): void
    {
        $this->hasParameters = $hasParameters;
    }

    public function isParameterSufficient($i): bool
    {
        foreach ($this->parameters as $parameter) {
            $index = $parameter[0];
            $sufficient = $parameter[4];

            if ($index === $i) {
                return $sufficient;
            }
        }

        return false;
    }

    public function isParameterFixed($i): bool
    {
        foreach ($this->parameters as $parameter) {
            $index = $parameter[0];
            $fixed = $parameter[3];

            if ($index === $i) {
                return $fixed;
            }
        }

        return false;
    }

    public function isParameterValidByDefault($i): bool
    {
        foreach ($this->parameters as $parameter) {
            $index = $parameter[0];
            $validbydefault = $parameter[2];

            if ($index === $i) {
                return $validbydefault;
            }
        }

        return false;
    }

    public function getParameterValues($i): ?array
    {
        foreach ($this->parameters as $parameter) {
            $index = $parameter[0];
            $values = $parameter[1];

            if ($index === $i) {
                return $values;
            }
        }

        return null;
    }

    public function setOrderNumberReal(int $orderNumberReal): void
    {
        $this->orderNumberReal = $orderNumberReal;
    }

    public function getOrderNumberReal(): int
    {
        return $this->orderNumberReal;
    }

    public function setOrderNumberExpected(int $orderNumberExpected): void
    {
        $this->orderNumberExpected = $orderNumberExpected;
    }

    public function getOrderNumberExpected(): int
    {
        return $this->orderNumberExpected;
    }

    public function getAction(): ?string
    {
        return $this->action;
    }

    public function setAction(?string $action): ?string
    {
        return $this->action = $action;
    }

    public function setMinNbArgs(int $minNbArgs): int
    {
        return $this->minNbArgs = $minNbArgs;
    }

    public function getMinNbArgs(): int
    {
        return $this->minNbArgs;
    }

    public function setMaxNbArgs(int $maxNbArgs): int
    {
        return $this->maxNbArgs = $maxNbArgs;
    }

    public function getMaxNbArgs(): int
    {
        return $this->maxNbArgs;
    }
}
