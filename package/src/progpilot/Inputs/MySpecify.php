<?php

/*
 * This file is part of ProgPilot, a static analyzer for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


namespace progpilot\Inputs;

class MySpecify
{
    private string $name;
    private string $language;
    private ?string $instanceOfName = null;
    private bool $isInstance;

    public function __construct(string $name, string $language)
    {
        $this->name = $name;
        $this->language = $language;
        $this->instanceOfName = null;
        $this->isInstance = false;
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function getLanguage(): string
    {
        return $this->language;
    }

    public function setIsInstance(bool $isInstance): void
    {
        $this->isInstance = $isInstance;
    }

    public function isInstance(): bool
    {
        return $this->isInstance;
    }

    public function getInstanceOfName(): string
    {
        return $this->instanceOfName;
    }

    public function setInstanceOfName(string $name): string
    {
        return $this->instanceOfName = $name;
    }
}
