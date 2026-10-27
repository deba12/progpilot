<?php

/*
 * This file is part of ProgPilot, a static analyzer for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


namespace progpilot\Representations;

class NodeCG
{
    private $myclass;
    private $name;
    private $line;
    private $column;
    private $file;
    private int $nbParents;
    private int $nbViews;
    private array $children;
    private string $color;

    public function __construct($name, $line, $column, $file, $myClass)
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

    public function getMyClass()
    {
        return $this->myclass;
    }

    public function setMyClass($myClass): void
    {
        $this->myclass = $myClass;
    }

    public function getName()
    {
        return $this->name;
    }

    public function getLine()
    {
        return $this->line;
    }

    public function getColumn()
    {
        return $this->column;
    }

    public function getFile()
    {
        return $this->file;
    }

    public function getNbParents()
    {
        return $this->nbParents;
    }

    public function getNbViews()
    {
        return $this->nbViews;
    }

    public function getChildren()
    {
        return $this->children;
    }

    public function getColor()
    {
        return $this->color;
    }

    public function setColor($color): void
    {
        $this->color = $color;
    }

    public function setChildren($children): void
    {
        $this->children = $children;
    }

    public function setNbViews($nbViews): void
    {
        $this->nbViews = $nbViews;
    }

    public function setNbParents($nbParents): void
    {
        $this->nbParents = $nbParents;
    }

    public function setName($name): void
    {
        $this->name = $name;
    }

    public function setLine($line): void
    {
        $this->line = $line;
    }

    public function setColumn($column): void
    {
        $this->column = $column;
    }

    public function setFile($file): void
    {
        $this->file = $file;
    }

    public function getId(): string
    {
        return hash("sha256", $this->name);
    }
}
