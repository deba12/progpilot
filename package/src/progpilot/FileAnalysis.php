<?php

/*
 * This file is part of ProgPilot, a static analyzer for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */

declare(strict_types=1);

namespace progpilot;

class FileAnalysis
{
    /**
     * @var string|bool
     */
    public string|bool $fullpath;
    /**
     * @var string
     */
    public string $basedir;

    public function __construct(string|bool $fullpath, string $basedir)
    {
        $this->fullpath = $fullpath;
        $this->basedir = $basedir;
    }
}
