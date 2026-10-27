<?php

/*
 * This file is part of ProgPilot, a static analyzer for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


declare(strict_types=1);

namespace progpilot\Objects;

class MyDefOriginal
{
    /**
     * @var list<MyDefinition|string|int>|null
     */
    private ?array $def = null;
    private string|int|null $arrayIndexAccessor = null;

    public function __construct()
    {
        $this->def = null;
        $this->arrayIndexAccessor = null;
    }

    /**
     * @return list<MyDefinition|string|int>|null
     */
    public function getDef(): ?array
    {
        return $this->def;
    }

    /**
     * @param list<MyDefinition|string|int> $myDef
     */
    public function setDef(array $myDef): void
    {
        $this->def = $myDef;
    }

    public function getArrayIndexAccessor(): string|int|null
    {
        return $this->arrayIndexAccessor;
    }

    public function setArrayIndexAccessor(string|int $arrayIndexAccessor): void
    {
        $this->arrayIndexAccessor = $arrayIndexAccessor;
    }
}
