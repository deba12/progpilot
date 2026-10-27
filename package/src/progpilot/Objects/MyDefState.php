<?php

/*
 * This file is part of ProgPilot, a static analyzer for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


namespace progpilot\Objects;

use stdClass;
use progpilot\Transformations\Php\Common;

class MyDefState extends MyOp
{
    private bool $isTainted;
    /**
     * @var list<array<mixed>>
     */
    private array $taintedByDefs;
    private bool $isSanitized;
    private array $typeSanitized;
    private array $lastKnownValue;
    private int $cast;
    private array $isEmbeddedByChar;
    private int $label;
    private int $objectId;
    private array $arrayIndexes;

    public function __construct()
    {
        parent::__construct("state", 0, 0);

        $this->isEmbeddedByChar = [];
        $this->isTainted = false;
        $this->taintedByDefs = [];
        $this->label = MyDefinition::SECURITY_LOW;
        $this->isSanitized = false;
        $this->typeSanitized = [];
        $this->lastKnownValue = [];
        $this->cast = MyDefinition::CAST_NOT_SAFE;
        $this->objectId = -1;
        $this->arrayIndexes = [];
    }

    public function printStdout(): void
    {
        echo "cast = " . $this->getCast() . "\n";

        if ($this->isTainted()) {
            echo "tainted = 1\n";

            foreach ($this->taintedByDefs as $taintedByDef) {
                echo "taintedByDef = '" . $taintedByDef[0]->getId() . "'\n";
            }
        }

        echo "last_known_value :\n";
        var_dump($this->lastKnownValue);
        echo "is_embeddedbychar :\n";
        var_dump($this->isEmbeddedByChar);
        echo "isSanitized :\n";
        var_dump($this->isSanitized);
        echo "type_sanitized :\n";
        var_dump($this->typeSanitized);
        echo "objectid :\n";
        var_dump($this->objectId);
        echo "istypeinstance : '" . $this->isType(MyDefinition::TYPE_INSTANCE) . "'\n";
        echo "allpropertiestainted : '" . $this->isType(MyDefinition::ALL_PROPERTIES_TAINTED) . "'\n";
        echo "allarrayelementstainted : '" . $this->isType(MyDefinition::ALL_ARRAY_ELEMENTS_TAINTED) . "'\n";
        echo "istypearray : '" . $this->isType(MyDefinition::TYPE_ARRAY) . "'\n";
        echo "istypearrayarray : '" . $this->isType(MyDefinition::TYPE_ARRAY_ARRAY) . "'\n";

        foreach ($this->arrayIndexes as $arrayIndex) {
            echo "index :\n";
            var_dump($arrayIndex->index);
            echo "def :\n";
            $arrayIndex->def->printStdout();
        }
    }

    /**
     * @param list<MyDefinition|MyDefState|MyProperty> $taintedByDef
     */
    public function addTaintedByDef(array $taintedByDef): void
    {
        if (!in_array($taintedByDef, $this->taintedByDefs, true)) {
            $this->taintedByDefs[] = $taintedByDef;
        }
    }

    /**
     * @return list<array<mixed>>
     */
    public function getTaintedByDefs(): array
    {
        return $this->taintedByDefs;
    }

    /**
     * @param list<array<mixed>> $defs
     */
    public function setTaintedByDefs(array $defs): void
    {
        $this->taintedByDefs = $defs;
    }

    /**
     * @param array<string, int> $chars
     */
    public function updateIsEmbeddedByChars(array $chars): void
    {
        foreach ($chars as $char => $value) {
            $curChar = isset($this->isEmbeddedByChar[$char]) ? $this->isEmbeddedByChar[$char] : 0;
            $this->isEmbeddedByChar[$char] = ($value + $curChar) % 2;
        }
    }

    /**
     * @param array<string, int> $chars
     */
    public function setIsEmbeddedByChars(array $chars): void
    {
        foreach ($chars as $char => $value) {
            $this->isEmbeddedByChar[$char] = $value % 2;
        }
    }

    /**
     * @return array<string, int>
     */
    public function getIsEmbeddedByChars(): array
    {
        return $this->isEmbeddedByChar;
    }

    public function setEmbeddedByChar(array $value): void
    {
        $this->isEmbeddedByChar = $value;
    }

    public function setIsEmbeddedByChar(mixed $char, $bool): void
    {
        $this->isEmbeddedByChar[$char] = $bool;
    }

    public function getIsEmbeddedByChar(string $char): bool|int
    {
        if (isset($this->isEmbeddedByChar[$char])) {
            return $this->isEmbeddedByChar[$char];
        }

        return false;
    }

    public function setLabel(int $label): void
    {
        $this->label = $label;
    }

    public function getLabel(): int
    {
        return $this->label;
    }

    public function setCast(int $cast): void
    {
        $this->cast = $cast;
    }

    public function getCast(): int
    {
        return $this->cast;
    }

    public function addLastKnownValue(string|int|bool|float $value): void
    {
        $value = rtrim(ltrim((string) $value));

        if (
            Common::validLastKnownValue($value)
            && !in_array($value, $this->lastKnownValue, true)
            && count($this->lastKnownValue) < 10
        ) {
            $this->lastKnownValue[] = $value;
        }
    }

    /**
     * @return list<string>
     */
    public function getLastKnownValues(): array
    {
        return $this->lastKnownValue;
    }

    public function setSanitized(bool $isSanitized): void
    {
        $this->isSanitized = $isSanitized;
    }

    public function isSanitized(): bool
    {
        return $this->isSanitized;
    }

    public function setTypeSanitized(array $typeSanitized): void
    {
        $this->typeSanitized = $typeSanitized;
    }

    /**
     * @return list<string>
     */
    public function getTypeSanitized(): array
    {
        return $this->typeSanitized;
    }

    public function addTypeSanitized(string $typeSanitized): void
    {
        if (!in_array($typeSanitized, $this->typeSanitized, true)) {
            $this->typeSanitized[] = $typeSanitized;
        }
    }

    public function isTypeSanitized(string $typeSanitized): bool
    {
        if (in_array($typeSanitized, $this->typeSanitized, true)) {
            return true;
        }

        return false;
    }

    public function isTainted(): bool
    {
        return $this->isTainted;
    }

    public function setTainted(bool $tainted): void
    {
        $this->isTainted = $tainted;
    }

    /**
     * @return list<bool|array<mixed>>
     */
    public function createDefArrayIndex(int $blockId, MyDefinition $myArrayDef, int|string $arrayIndex): array
    {
        $myDef = new MyDefinition(
            $blockId,
            $myArrayDef->getSourceMyFile(),
            $myArrayDef->getLine(),
            $myArrayDef->getColumn(),
            "built-in-index-array"
        );

        $myDef->addType(MyDefinition::TYPE_ARRAY_ELEMENT);
        $this->addArrayIndex($arrayIndex, $myDef);
        $this->addType(MyDefinition::TYPE_ARRAY);
        $ret[] = $myDef;

        $existingState = $myArrayDef->getState($blockId);

        if (!is_null($existingState) && $existingState->isType(MyDefinition::ALL_ARRAY_ELEMENTS_TAINTED)) {
            $myDef->requireCurrentState()->setTainted(true);
            $myDef->requireCurrentState()->addTaintedByDef([$myArrayDef, $myArrayDef->getCurrentState()]);
        } elseif ($myArrayDef->requireCurrentState()->isType(MyDefinition::ALL_ARRAY_ELEMENTS_TAINTED)) {
            // data/source17.php
            $myDef->requireCurrentState()->setTainted(true);
            $myDef->requireCurrentState()->addTaintedByDef([$myArrayDef, $myArrayDef->getCurrentState()]);
        }

        return [true, $ret];
    }

    /**
     * @return list<bool|array<mixed>>
     */
    public function getOrCreateDefArrayIndex(int $blockId, MyDefinition $myArrayDef, int|string $arrayIndex): array
    {
        $ret = [];
        $found = false;
        for ($i = 0; $i < count($this->arrayIndexes); $i++) {
            if ($this->arrayIndexes[$i]->index === $arrayIndex) {
                $found = true;
                $ret[] = $this->arrayIndexes[$i]->def;
            }
        }

        if ($found) {
            return [false, $ret];
        }

        return $this->createDefArrayIndex($blockId, $myArrayDef, $arrayIndex);
    }

    public function isArrayIndexExists(int|string $arrayIndex): bool
    {
        for ($i = 0; $i < count($this->arrayIndexes); $i++) {
            if ($this->arrayIndexes[$i]->index === $arrayIndex) {
                return true;
            }
        }

        return false;
    }

    public function addArrayIndex(int|string $arrayIndex, MyDefinition $def): bool
    {
        if (
            !$this->isArrayIndexExists($arrayIndex)
            && count($this->arrayIndexes) < 100
        ) {
            $ele = new stdClass();
            $ele->index = $arrayIndex;
            $ele->def = $def;
            $this->arrayIndexes[] = $ele;

            return true;
        }

        return false;
    }

    public function overwriteArrayIndex(int $arrayIndex, MyDefinition $def): void
    {
        for ($i = 0; $i < count($this->arrayIndexes); $i++) {
            if ($this->arrayIndexes[$i]->index === $arrayIndex) {
                $this->arrayIndexes[$i]->def = $def;
                break;
            }
        }
    }

    public function setArrayIndexes(array $arrayIndexes): void
    {
        $this->arrayIndexes = $arrayIndexes;
    }

    /**
     * @return list<stdClass>
     */
    public function getArrayIndexes(): array
    {
        return $this->arrayIndexes;
    }

    public function getObjectId(): int
    {
        return $this->objectId;
    }

    public function setObjectId(int $objectId): void
    {
        $this->objectId = $objectId;
    }
}
