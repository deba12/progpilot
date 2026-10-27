<?php

/*
 * This file is part of ProgPilot, a static analyzer for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


namespace progpilot\Objects;

use progpilot\Context;

class MyClass extends MyOp
{
    private array $methods;
    private array $properties;
    private ?string $extendsof = null;

    public function __construct($varLine, $varColumn, $varName)
    {
        parent::__construct($varName, $varLine, $varColumn);

        $this->properties = [];
        $this->methods = [];
        $this->extendsof = null;
    }

    public function __clone()
    {
        for ($i = 0; $i < count($this->properties); $i++) {
            $this->properties[$i] = clone $this->properties[$i];
        }

        for ($i = 0; $i < count($this->methods); $i++) {
            $this->methods[$i] = clone $this->methods[$i];
        }
    }

    public function addMethod(MyFunction $method): void
    {
        $exist = false;
        foreach ($this->methods as $methodClass) {
            if ($methodClass->getName() === $method->getName()) {
                $exist = true;
                break;
            }
        }

        if (!$exist) {
            $this->methods[] = $method;
        }
    }

    public function getMethod(string $name): ?MyFunction
    {
        foreach ($this->methods as $method) {
            if ($method->getName() === $name) {
                return $method;
            }
        }

        return null;
    }

    /**
     * @return list<MyFunction>
     */
    public function getMethods(): array
    {
        return $this->methods;
    }

    /**
     * @return list<MyProperty>
     */
    public function getProperties(): array
    {
        return $this->properties;
    }

    public function addProperty(MyProperty $property): void
    {
        $exist = false;
        foreach ($this->properties as $defClass) {
            if ($defClass->getName() === $property->getName()) {
                $exist = true;
                break;
            }
        }

        if (!$exist) {
            $this->properties[] = $property;
        }
    }

    public function getProperty(Context $context, int $blockid, MyDefinition $instance, string $name): ?MyProperty
    {
        foreach ($this->properties as $def) {
            // we don't check if it's STATIC property or NOT
            if ($def->getName() === $name) {
                return $def;
            }
        }

        // we didn't find any propery but in this case php create automatically the property
        // same code than in selectproperties resolvedef
        $myProperty = new MyProperty(
            $context->requireCurrentBlock()->getId(),
            $context->getCurrentMyFile(),
            $instance->getLine(),
            $instance->getColumn(),
            $name
        );
        $myProperty->setVisibility("public");
        $this->addProperty($myProperty);

        $state = $instance->getState($blockid);
        if (!is_null($state) && $state->isType(MyDefinition::ALL_PROPERTIES_TAINTED)) {
            $myProperty->requireCurrentState()->setTainted(true);
            $myProperty->requireCurrentState()->addTaintedByDef([$instance, $state]);
        }

        return $myProperty;
    }

    public function getExtendsOf(): ?string
    {
        return $this->extendsof;
    }

    public function setExtendsOf(string $extendsof): void
    {
        $this->extendsof = $extendsof;
    }
}
