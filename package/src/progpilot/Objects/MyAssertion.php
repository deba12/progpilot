<?php

/*
 * This file is part of ProgPilot, a static analyzer for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


namespace progpilot\Objects;

class MyAssertion
{
    private string $typeAssertion;
    private MyDefinition $mydef;

    public function __construct(MyDefinition $myDef, string $typeAssertion)
    {
        $this->typeAssertion = $typeAssertion;
        $this->mydef = $myDef;
    }

    public function addDef(MyDefinition $myDef): void
    {
        $this->mydef = $myDef;
    }

    public function getDef(): MyDefinition
    {
        return $this->mydef;
    }

    public function addType(string $typeAssertion): void
    {
        $this->typeAssertion = $typeAssertion;
    }

    public function getType(): string
    {
        return $this->typeAssertion;
    }
}
