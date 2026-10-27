<?php

/*
 * This file is part of ProgPilot, a static analyzer for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


declare(strict_types=1);

namespace progpilot\Dataflow;

use progpilot\Objects\MyFunction;

class Functions
{
    /**
     * @var array<mixed>
     */
    private array $functions;

    public function __construct()
    {
        $this->functions = [];
    }

    /**
     * @return mixed[]
     */
    public function getAllFunctions(string $funcname, string $className = "function"): array
    {
        $functionsTmp = [];

        foreach ($this->functions as $id => $functionsFile) {
            if (isset($functionsFile[$className][$funcname])) {
                $functionsTmp[] = $functionsFile[$className][$funcname];
            }
        }

        return $functionsTmp;
    }


    public function getFunction(string $funcname, ?string $className = null, ?string $specificFile = null): ?MyFunction
    {
        if (is_null($className)) {
            $className = "function";
        }

        if (!is_null($specificFile)) {
            if (isset($this->functions[$specificFile][$className][$funcname])) {
                return $this->functions[$specificFile][$className][$funcname];
            }
        } else {
            foreach ($this->functions as $id => $functionsFile) {
                if (isset($functionsFile[$className][$funcname])) {
                    return $functionsFile[$className][$funcname];
                }
            }
        }

        return null;
    }

    /**
     * @return array<string, array<mixed>>
     */
    public function getFunctions(): array
    {
        return $this->functions;
    }

    public function addFunction(mixed $filenamehash, string $classname, string $funcname, MyFunction $myFunc): void
    {
        $this->functions[$filenamehash][$classname][$funcname] = $myFunc;
    }

    public function delFunction(string $filenamehash, string $classname, string $funcname): ?MyFunction
    {
        $save = null;

        if (isset($this->functions[$filenamehash][$classname][$funcname])) {
            $save = $this->functions[$filenamehash][$classname][$funcname];
            $this->functions[$filenamehash][$classname][$funcname] = null;
        }

        return $save;
    }
}
