<?php

/*
 * This file is part of ProgPilot, a static analyzer for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


namespace progpilot\Objects;

use progpilot\Objects\MyOp;

class MyDefinition extends MyOp
{
    public const CAST_SAFE = 1;
    public const CAST_NOT_SAFE = 2;

    public const TYPE_PROPERTY = 0x0001;
    public const TYPE_ARRAY = 0x0002;
    public const TYPE_CONSTANTE = 0x0004;
    public const TYPE_REFERENCE = 0x0008;
    public const TYPE_ARRAY_REFERENCE = 0x0010;
    public const TYPE_ARRAY_ELEMENT = 0x0020;
    public const TYPE_INSTANCE = 0x0040;
    public const TYPE_GLOBAL = 0x0080;
    public const TYPE_STATIC_PROPERTY = 0x0100;
    public const ALL_PROPERTIES_TAINTED = 0x0200;
    public const ALL_ARRAY_ELEMENTS_TAINTED = 0x0400;
    public const TYPE_LITERAL = 0x0800;
    public const TYPE_ITERATOR = 0x1000;
    public const TYPE_ARRAY_ARRAY = 0x2000;

    public const SECURITY_HIGH = 1;
    public const SECURITY_LOW = 2;

    private $blockId;
    private string $className;
    private bool $returnedFromValidator;
    private bool $validWhenReturning;
    private bool $validNotBoolean;
    private $paramToArg;
    private $argToParam;
    private $isReturnDef;
    private array $refs;
    private array $iteratorValues;
    private array $blocksIdsStates;
    private $returnDef;

    /**
     * @var \progpilot\Objects\MyDefOriginal
     */
    public $original;
    public $states;

    public function __construct($blockId, $myFile, $varLine, $varColumn, $varName)
    {
        parent::__construct($varName, $varLine, $varColumn);

        $this->setSourceMyFile($myFile);
        $this->blockId = $blockId;
        $this->className = "";
        $this->returnedFromValidator = false;
        $this->validWhenReturning = false;
        $this->validNotBoolean = false;
        $this->paramToArg = null;
        $this->argToParam = null;
        $this->isReturnDef = null;
        $this->refs = [];
        $this->iteratorValues = [];

        $this->original = new MyDefOriginal();
        $this->states = [];
        $this->blocksIdsStates = [];

        // original state
        $state = $this->createState();
        $this->assignStateToBlockId($state->getId(), $blockId);
    }

    public function printStdout($context = null): void
    {
        echo "_____________________ start def _____________________\n";
        echo "def id " . $this->varId . " :: \
        name = " . htmlentities($this->getName(), ENT_QUOTES, 'UTF-8') . " :: \
        line = " . $this->getLine() . " :: column = " . $this->getColumn() . " :: \
        ref = " . $this->isType(MyDefinition::TYPE_REFERENCE) . " :: \
        is_property = " . $this->isType(MyDefinition::TYPE_PROPERTY) . " :: \
        is_static_property = " . $this->isType(MyDefinition::TYPE_STATIC_PROPERTY) . " :: \
        is_type_array_element = " . $this->isType(MyDefinition::TYPE_ARRAY_ELEMENT) . " :: \
        isArray = " . $this->isType(MyDefinition::TYPE_ARRAY) . " :: \
        is_const = " . $this->isType(MyDefinition::TYPE_CONSTANTE) . " :: \
        is_iterator = " . $this->isType(MyDefinition::TYPE_ITERATOR) . " :: \
        is_return_def = " . $this->isReturnDef . " :: \
        blockid = " . $this->getBlockId() . "\n";

        if (!is_null($this->getParamToArg())) {
            echo "it's a param (to arg possibility) start ===\n";
            $this->getParamToArg()->printStdout();
            echo "it's a param (to arg possibility) end ===\n";
        }

        $this->getSourceMyFile()->printStdout();

        foreach ($this->states as $id => $state) {
            echo "state id '$id'\n";
            echo "__________________ start state ________________________\n";
            $state->printStdout();
            echo "__________________ end state________________________\n";
        }

        echo "_____________________ states blocks associations _____________________\n\n\n";
        var_dump($this->blocksIdsStates);
        echo "_____________________ end def _____________________\n\n\n";
    }

    public function unsetState(mixed $blockId): void
    {
        unset($this->blocksIdsStates[$blockId]);
    }

    public function setStatesToBlocksIds($statesToBlocksIds): void
    {
        $this->blocksIdsStates = $statesToBlocksIds;
    }

    public function getStatesToBlocksIds()
    {
        return $this->blocksIdsStates;
    }

    public function setStates($states): void
    {
        $this->states = $states;
    }

    public function assignStateToBlockId($stateId, $blockId): void
    {
        if (
            isset($this->blocksIdsStates[$blockId])
            && $blockId !== $this->getBlockId()
        ) {
            $toRemove = true;
            $overWrittentStateId = $this->blocksIdsStates[$blockId];
            foreach ($this->blocksIdsStates as $keyBlockId => $valueStateId) {
                if (
                    $valueStateId === $overWrittentStateId
                    && $keyBlockId !== $blockId
                ) {
                    $toRemove = false;
                    break;
                }
            }

            if ($toRemove) {
                unset($this->states[$overWrittentStateId]);
            }
        }

        $this->blocksIdsStates[$blockId] = $stateId;
    }

    public function createState(): \progpilot\Objects\MyDefState
    {
        $state = new MyDefState();
        $this->states[$state->getId()] = $state;

        return $state;
    }

    public function addState($newstate): void
    {
        $this->states[$newstate->getId()] = $newstate;
    }

    public function getCurrentState()
    {
        if (isset($this->blocksIdsStates[$this->blockId])) {
            $stateId = $this->blocksIdsStates[$this->blockId];
            if (isset($this->states[$stateId])) {
                return $this->states[$stateId];
            }
        }

        return null;
    }

    public function getNbStates(): int
    {
        return count($this->states);
    }

    public function getStates()
    {
        return $this->states;
    }

    public function getState($blockId)
    {
        if (isset($this->blocksIdsStates[$blockId])) {
            $stateId = $this->blocksIdsStates[$blockId];
            if (isset($this->states[$stateId])) {
                return $this->states[$stateId];
            }
        }

        return null;
    }

    public function setArgToParam($def): void
    {
        $this->argToParam = $def;
    }

    public function getArgToParam()
    {
        return $this->argToParam;
    }

    public function setParamToArg($def): void
    {
        $this->paramToArg = $def;
    }

    public function getParamToArg()
    {
        return $this->paramToArg;
    }

    public function setValidWhenReturning($value): void
    {
        $this->validWhenReturning = $value;
    }

    public function getValidWhenReturning()
    {
        return $this->validWhenReturning;
    }

    public function setValidNotBoolean($value): void
    {
        $this->validNotBoolean = $value;
    }

    public function getValidNotBoolean()
    {
        return $this->validNotBoolean;
    }

    public function setReturnedFromValidator($value): void
    {
        $this->returnedFromValidator = $value;
    }

    public function getReturnedFromValidator()
    {
        return $this->returnedFromValidator;
    }

    public function getClassName()
    {
        return $this->className;
    }

    public function setClassName($className): void
    {
        $this->className = $className;
    }

    public function getRefs()
    {
        return $this->refs;
    }

    public function setRefs($refs): void
    {
        $this->refs = $refs;
    }

    public function getIteratorValues()
    {
        return $this->iteratorValues;
    }

    public function setIteratorValues($iteratorValues): void
    {
        $this->iteratorValues = $iteratorValues;
    }

    public function getBlockId()
    {
        return $this->blockId;
    }

    public function setBlockId($blockId): void
    {
        $this->blockId = $blockId;
    }

    public function isReturnDef()
    {
        return $this->returnDef;
    }

    public function setReturnDef($returnDef): void
    {
        $this->returnDef = $returnDef;
    }
}
