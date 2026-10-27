<?php

/*
 * This file is part of ProgPilot, a static analyzer for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


declare(strict_types=1);

namespace progpilot\Inputs;

class MyVuln
{
    private string $vulnId;

    public function __construct(string $vulnId)
    {
        $this->vulnId = $vulnId;
    }

    public function getId(): string
    {
        return $this->vulnId;
    }

    public function setId(string $vulnId): string
    {
        return $this->vulnId = $vulnId;
    }
}
