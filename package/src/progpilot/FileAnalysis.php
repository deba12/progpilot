<?php

/*
 * This file is part of ProgPilot, a static analyzer for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */

namespace progpilot;

class FileAnalysis
{
    public $fullpath;
    public $basedir;

    public function __construct($fullpath, $basedir)
    {
        $this->fullpath = $fullpath;
        $this->basedir = $basedir;
    }
}
