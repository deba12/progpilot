<?php

/*
 * This file is part of ProgPilot, a static analyzer for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


namespace progpilot\Dataflow;

class Objects
{
    private array $objects;

    public function __construct()
    {
        $this->objects = [];
    }

    public function getObjects()
    {
        return $this->objects;
    }

    public function addObject(): int
    {
        $idObject = count($this->objects);
        $this->objects[$idObject] = null;

        return $idObject;
    }

    public function addMyclassToObject(mixed $idObject, $myClass): void
    {
        $this->objects[$idObject] = $myClass;
    }

    public function getMyClassFromObject($idObject)
    {
        if (isset($this->objects[$idObject])) {
            return $this->objects[$idObject];
        }

        return null;
    }
}
