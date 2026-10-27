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
    private array $arrayValue;
    private $returnArrayValue;
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

    public function getIsReturnArray()
    {
        return $this->isReturnArray;
    }

    public function setReturnArray($arr): void
    {
        $this->isReturnArray = $arr;
    }

    public function setReturnArrayValue($arr): void
    {
        $this->returnArrayValue = $arr;
    }

    public function getReturnArrayValue()
    {
        return $this->returnArrayValue;
    }

    public function getLabel()
    {
        return $this->label;
    }

    public function setLabel($label): void
    {
        $this->label = $label;
    }

    public function getIsObject()
    {
        return $this->isObject;
    }

    public function setIsObject($isObject): void
    {
        $this->isObject = $isObject;
    }

    public function getIsArrayOfObjects()
    {
        return $this->isArrayOfObjects;
    }

    public function setIsArrayOfObjects($isArrayOfObjects): void
    {
        $this->isArrayOfObjects = $isArrayOfObjects;
    }

    public function getIsArrayOfArrays()
    {
        return $this->isArrayOfArrays;
    }

    public function setIsArrayOfArrays($isArrayOfArrays): void
    {
        $this->isArrayOfArrays = $isArrayOfArrays;
    }

    public function getIsArray()
    {
        return $this->isArray;
    }

    public function setIsArray($isArray): void
    {
        $this->isArray = $isArray;
    }

    public function isAnArrayValue($arr): bool
    {
        if (in_array($arr, $this->arrayValue, true)) {
            return true;
        }

        return false;
    }

    public function getArrayValue()
    {
        return $this->arrayValue;
    }

    public function setArrayValue($arrayValue): void
    {
        $this->arrayValue = $arrayValue;
    }

    public function isFunction()
    {
        return $this->isFunction;
    }

    public function setIsFunction($isFunction): void
    {
        $this->isFunction = $isFunction;
    }

    public function addconditionsParameter(mixed $parameter, $conditions, $value): void
    {
        $this->conditionsParameters[$parameter][] = [$conditions, $value];
    }

    public function getconditionsParameter(mixed $parameter, $conditions)
    {
        foreach ($this->conditionsParameters[$parameter] as $conditionsParam) {
            if ($conditionsParam[0] === $conditions) {
                return $conditionsParam[1];
            }
        }

        return null;
    }

    public function addParameter($parameter): void
    {
        $this->parameters[] = $parameter;
    }

    public function getParameters()
    {
        return $this->parameters;
    }

    public function isParameter($i): bool
    {
        foreach ($this->parameters as $parameter) {
            if ($parameter === $i) {
                return true;
            }
        }

        return false;
    }

    public function hasParameters()
    {
        return $this->hasParameters;
    }

    public function setHasParameters($hasParameters): void
    {
        $this->hasParameters = $hasParameters;
    }
}
