<?php

/*
 * This file is part of ProgPilot, a static analyzer for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


declare(strict_types=1);

namespace progpilot\Representations;

use progpilot\Objects\MyClass;

class NodeCG
{
    private ?MyClass $myclass;
    private string $name;
    private int $line;
    private int $column;
    private string $file;
    private int $nbParents;
    private int $nbViews;
    /**
     * @var list<string>
     */
    private array $children;
    private string $color;

    public function __construct(string $name, int $line, int $column, string $file, ?MyClass $myClass)
    {
        $this->myclass = $myClass;
        $this->name = $name;
        $this->line = $line;
        $this->column = $column;
        $this->file = $file;

        $this->nbParents = 0;
        $this->nbViews = 0;
        $this->children = [];
        $this->color = "white";
    }

    public function getMyClass(): ?MyClass
    {
        return $this->myclass;
    }

    public function setMyClass(?MyClass $myClass): void
    {
        $this->myclass = $myClass;
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function getLine(): int
    {
        return $this->line;
    }

    public function getColumn(): int
    {
        return $this->column;
    }

    public function getFile(): string
    {
        return $this->file;
    }

    public function getNbParents(): int
    {
        return $this->nbParents;
    }

    public function getNbViews(): int
    {
        return $this->nbViews;
    }

    /**
     * @return list<string>
     */
    public function getChildren(): array
    {
        return $this->children;
    }

    public function getColor(): string
    {
        return $this->color;
    }

    public function setColor(string $color): void
    {
        $this->color = $color;
    }

    /**
     * @param list<string> $children
     */
    public function setChildren(array $children): void
    {
        $this->children = $children;
    }

    public function setNbViews(int $nbViews): void
    {
        $this->nbViews = $nbViews;
    }

    public function setNbParents(int $nbParents): void
    {
        $this->nbParents = $nbParents;
    }

    public function setName(string $name): void
    {
        $this->name = $name;
    }

    public function setLine(int $line): void
    {
        $this->line = $line;
    }

    public function setColumn(int $column): void
    {
        $this->column = $column;
    }

    public function setFile(string $file): void
    {
        $this->file = $file;
    }

    public function getId(): string
    {
        return hash("sha256", $this->name);
    }
}
