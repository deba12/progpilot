<?php

/*
 * This file is part of ProgPilot, a static analyzer for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


namespace progpilot\Code;

use progpilot\Objects\MyBlock;
use progpilot\Objects\MyFunction;
use progpilot\Objects\MyClass;
use progpilot\Objects\MyDefinition;

class MyInstruction
{
    public const MYBLOCK = 1;
    public const MYBLOCK_IF = 2;
    public const MYBLOCK_ELSE = 3;
    public const MYFUNC = 4;
    public const NOT_BOOLEAN = 5;
    public const MYCLASS = 7;
    public const DEF = 8;
    public const RETURN_DEFS = 9;
    public const FUNCNAME = 10;
    public const TYPE_INCLUDE = 11;
    public const MYFUNC_CALL = 12;
    public const PHI = 15;
    public const ORIGINAL_DEF = 16;
    public const ARRAY_DIM = 17;
    public const PROPERTY_NAME = 18;
    public const VARID = 19;
    public const RESULTID = 20;
    public const VARIABLE_NAME = 21;
    public const VARIABLE = 22;
    public const LITERAL = 23;
    public const EXPRID = 24;
    public const LEFTID = 25;
    public const RIGHTID = 26;
    public const REFERENCE = 27;

    private array $properties;
    private int $opcode;

    public function __construct(int $opcode)
    {
        $this->properties = [];
        $this->opcode = $opcode;
    }

    public function addProperty(mixed $index, mixed $property): void
    {
        $this->properties[$index] = $property;
    }

    public function isPropertyExist(mixed $index): bool
    {
        return isset($this->properties[$index]);
    }

    /**
     * The properties are set by the transformation step according to the opcode, the type depends on the key.
     * Dynamic keys (argdefN, keyN, valueN, ...) are not described here and give mixed.
     *
     * @return ($index is self::MYBLOCK|self::MYBLOCK_IF|self::MYBLOCK_ELSE ? MyBlock
     *     : ($index is self::MYFUNC|self::MYFUNC_CALL ? MyFunction
     *     : ($index is self::MYCLASS ? MyClass
     *     : ($index is self::DEF ? MyDefinition|null
     *     : ($index is self::ORIGINAL_DEF ? MyDefinition|null
     *     : ($index is self::FUNCNAME|self::PROPERTY_NAME ? string
     *     : ($index is self::VARID ? int|null
     *     : ($index is self::TYPE_INCLUDE|self::RESULTID|self::EXPRID|self::LEFTID ? int
     *     : ($index is self::ARRAY_DIM ? int|string
     *     : ($index is self::RIGHTID ? int|array<mixed>
     *     : ($index is self::RETURN_DEFS ? array<mixed>
     *     : ($index is self::REFERENCE ? bool : mixed))))))))))))
     */
    public function getProperty(int|string $index): mixed
    {
        if (isset($this->properties[$index])) {
            return $this->properties[$index];
        }

        return null;
    }

    public function getOpcode(): int
    {
        return $this->opcode;
    }
}
