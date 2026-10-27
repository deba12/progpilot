<?php

/*
 * This file is part of ProgPilot, a static analyzer for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


namespace progpilot\Inputs;

class MyInclude
{
    private int $line;
    private int $column;
    private string $sourceFile;
    private string $value;

    public function __construct(int $line, int $column, string $sourceFile, string $value)
    {
        $this->line = $line;
        $this->column = $column;
        $this->sourceFile = $sourceFile;
        $this->value = $value;
    }

    public function getLine(): int
    {
        return $this->line;
    }

    public function getColumn(): int
    {
        return $this->column;
    }

    public function getSourceFile(): string
    {
        return $this->sourceFile;
    }

    public function getValue(): string
    {
        return $this->value;
    }
}
