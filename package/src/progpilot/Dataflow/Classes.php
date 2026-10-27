<?php

/*
 * This file is part of ProgPilot, a static analyzer for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


declare(strict_types=1);

namespace progpilot\Dataflow;

use progpilot\Objects\MyClass;

class Classes
{
    /**
     * @var array<string, MyClass>
     */
    private array $listClasses;

    public function __construct()
    {
        $this->listClasses = [];
    }

    /**
     * @return array<string, MyClass>
     */
    public function getListClasses(): array
    {
        return $this->listClasses;
    }

    public function addMyclass(MyClass $newMyClass): void
    {
        if (!isset($this->listClasses[$newMyClass->getName()])) {
            $this->listClasses[$newMyClass->getName()] = $newMyClass;
        }
    }

    public function getMyClass(string $name): ?MyClass
    {
        if (isset($this->listClasses[$name])) {
            return $this->listClasses[$name];
        }

        return null;
    }
}
