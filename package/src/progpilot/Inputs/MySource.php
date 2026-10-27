<?php

/*
 * This file is part of ProgPilot, a static analyzer for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


namespace progpilot\Inputs;

use progpilot\Objects\MyDefinition;

class MySource extends MySpecify
{
    private bool $isObject;
    private bool $isArrayOfObjects;
    private bool $isArrayOfArrays;
    private bool $isArray;
    private bool $isFunction;
    /**
     * @var list<string>
     */
    private array $arrayValue;
    private ?string $returnArrayValue = null;
    private bool $isReturnArray;
    private array $parameters;
    private array $conditionsParameters;
    private bool $hasParameters;
    private int $label;

    public const CONDITION_ARRAY = "condition_array";

    public function __construct($name, $language)
    {
        parent::__construct($name, $language);

        $this->isObject = false;
        $this->isArrayOfObjects = false;
        $this->isArrayOfArrays = false;
        $this->isFunction = false;
        $this->returnArrayValue = null;
        $this->isReturnArray = false;
        $this->arrayValue = [];
        $this->isArray = false;
        $this->hasParameters = false;
        $this->parameters = [];
        $this->conditionsParameters = [];
        $this->label = MyDefinition::SECURITY_LOW;
    }

    public function getIsReturnArray(): bool
    {
        return $this->isReturnArray;
    }

    public function setReturnArray(bool $arr): void
    {
        $this->isReturnArray = $arr;
    }

    public function setReturnArrayValue(string $arr): void
    {
        $this->returnArrayValue = $arr;
    }

    public function getReturnArrayValue(): ?string
    {
        return $this->returnArrayValue;
    }

    public function getLabel(): int
    {
        return $this->label;
    }

    public function setLabel(int $label): void
    {
        $this->label = $label;
    }

    public function getIsObject(): bool
    {
        return $this->isObject;
    }

    public function setIsObject(bool $isObject): void
    {
        $this->isObject = $isObject;
    }

    public function getIsArrayOfObjects(): bool
    {
        return $this->isArrayOfObjects;
    }

    public function setIsArrayOfObjects(bool $isArrayOfObjects): void
    {
        $this->isArrayOfObjects = $isArrayOfObjects;
    }

    public function getIsArrayOfArrays(): bool
    {
        return $this->isArrayOfArrays;
    }

    public function setIsArrayOfArrays(bool $isArrayOfArrays): void
    {
        $this->isArrayOfArrays = $isArrayOfArrays;
    }

    public function getIsArray(): bool
    {
        return $this->isArray;
    }

    public function setIsArray(bool $isArray): void
    {
        $this->isArray = $isArray;
    }

    public function isAnArrayValue(string|int|null $arr): bool
    {
        if (in_array($arr, $this->arrayValue, true)) {
            return true;
        }

        return false;
    }

    /**
     * @return list<string>
     */
    public function getArrayValue(): array
    {
        return $this->arrayValue;
    }

    /**
     * @param list<string> $arrayValue
     */
    public function setArrayValue(array $arrayValue): void
    {
        $this->arrayValue = $arrayValue;
    }

    public function isFunction(): bool
    {
        return $this->isFunction;
    }

    public function setIsFunction(bool $isFunction): void
    {
        $this->isFunction = $isFunction;
    }

    public function addconditionsParameter(mixed $parameter, string $conditions, int $value): void
    {
        $this->conditionsParameters[$parameter][] = [$conditions, $value];
    }

    public function getconditionsParameter(mixed $parameter, string $conditions): ?int
    {
        foreach ($this->conditionsParameters[$parameter] as $conditionsParam) {
            if ($conditionsParam[0] === $conditions) {
                return $conditionsParam[1];
            }
        }

        return null;
    }

    public function addParameter(int $parameter): void
    {
        $this->parameters[] = $parameter;
    }

    public function getParameters(): array
    {
        return $this->parameters;
    }

    public function isParameter(int $i): bool
    {
        foreach ($this->parameters as $parameter) {
            if ($parameter === $i) {
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
