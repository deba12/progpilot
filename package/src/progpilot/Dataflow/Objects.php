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

class Objects
{
    /**
     * @var list<MyClass|null>
     */
    private array $objects;

    public function __construct()
    {
        $this->objects = [];
    }

    /**
     * @return list<MyClass|null>
     */
    public function getObjects(): array
    {
        return $this->objects;
    }

    public function addObject(): int
    {
        $idObject = count($this->objects);
        $this->objects[$idObject] = null;

        return $idObject;
    }

    public function addMyclassToObject(mixed $idObject, MyClass $myClass): void
    {
        $this->objects[$idObject] = $myClass;
    }

    public function getMyClassFromObject(int $idObject): ?MyClass
    {
        if (isset($this->objects[$idObject])) {
            return $this->objects[$idObject];
        }

        return null;
    }
}
