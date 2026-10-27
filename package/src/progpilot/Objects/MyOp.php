<?php

/*
 * This file is part of ProgPilot, a static analyzer for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


namespace progpilot\Objects;

class MyOp
{
    public static ?int $nbObjects = null;
    protected ?int $varId = null;

    private string $varName;
    private int $varLine;
    private int $varColumn;
    private ?MyFile $sourceMyFile = null;

    private int $flags;

    public const TYPE_VARIABLE = "type_variable";
    public const TYPE_LITERAL = "type_literal";
    public const TYPE_ARRAY = "type_array";
    public const TYPE_ARRAY_EXPR = "type_array_expr";
    public const TYPE_ARRAY_ELEMENT = "type_array_element";
    public const TYPE_METHOD = "type_method";
    public const TYPE_INSTANCE = "type_instance";
    public const TYPE_PROPERTY = "type_property";
    public const TYPE_FUNCCALL = "type_funccall";
    public const TYPE_FUNCCALL_ARRAY = "type_funccall_array";
    public const TYPE_CONST = "type_const";
    public const TYPE_STATIC_PROPERTY = "type_static_property";

    public function __construct(string $varName, int $varLine, int $varColumn)
    {
        $this->flags = 0;
        $this->varId = MyOp::$nbObjects++;
        $this->varName = $varName;
        $this->varLine = $varLine;
        $this->varColumn = $varColumn;
        $this->sourceMyFile = null;
    }

    public function __clone()
    {
        $this->varId = MyOp::$nbObjects++;
    }

    public function setType(int $flags): void
    {
        $this->flags = $flags;
    }

    public function getType(): int
    {
        return $this->flags;
    }

    public function isType(int $type): bool
    {
        return (bool) ($this->flags & $type);
    }

    public function addType(int $type): void
    {
        $this->flags |= $type;
    }

    public function removeType(int $type): void
    {
        if ($this->isType($type)) {
            $this->flags ^= $type;
        }
    }

    public function setId(int $varId): void
    {
        $this->varId = $varId;
    }

    public function getId(): ?int
    {
        return $this->varId;
    }

    public function getLine(): int
    {
        return $this->varLine;
    }

    public function getColumn(): int
    {
        return $this->varColumn;
    }

    public function setLine(int $line): void
    {
        $this->varLine = $line;
    }

    public function setColumn(int $column): void
    {
        $this->varColumn = $column;
    }

    public function getSourceMyFile(): ?MyFile
    {
        return $this->sourceMyFile;
    }

    public function setSourceMyFile(MyFile $sourceMyFile): void
    {
        $this->sourceMyFile = $sourceMyFile;
    }

    public function setName(string $varName): void
    {
        $this->varName = $varName;
    }

    public function getName(): string
    {
        return $this->varName;
    }
}
