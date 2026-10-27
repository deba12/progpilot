<?php

/*
 * This file is part of ProgPilot, a static analyzer for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


namespace progpilot\Objects;

use LogicException;
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

    private int $blockId;
    private string $className;
    private bool $returnedFromValidator;
    private bool $validWhenReturning;
    private bool $validNotBoolean;
    private ?MyDefinition $paramToArg = null;
    private ?MyDefinition $argToParam = null;
    /**
     * @var list<MyDefinition>
     */
    private array $refs;
    /**
     * @var list<MyDefinition>
     */
    private array $iteratorValues;
    /**
     * @var array<int, int>
     */
    private array $blocksIdsStates;
    private ?bool $returnDef = null;

    /**
     * @var MyDefOriginal
     */
    public MyDefOriginal $original;
    /**
     * @var array<int|string, MyDefState>
     */
    public array $states;

    public function __construct(int $blockId, MyFile $myFile, int $varLine, int $varColumn, string $varName)
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
        $this->refs = [];
        $this->iteratorValues = [];

        $this->original = new MyDefOriginal();
        $this->states = [];
        $this->blocksIdsStates = [];

        // original state
        $state = $this->createState();
        $this->assignStateToBlockId($state->getId(), $blockId);
    }

    public function printStdout(mixed $context = null): void
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
        is_return_def = " . (int) $this->returnDef . " :: \
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

    /**
     * @param array<int, int> $statesToBlocksIds
     */
    public function setStatesToBlocksIds(array $statesToBlocksIds): void
    {
        $this->blocksIdsStates = $statesToBlocksIds;
    }

    /**
     * @return array<int, int>
     */
    public function getStatesToBlocksIds(): array
    {
        return $this->blocksIdsStates;
    }

    /**
     * @param array<int|string, MyDefState> $states
     */
    public function setStates(array $states): void
    {
        $this->states = $states;
    }

    public function assignStateToBlockId(int $stateId, int $blockId): void
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

    public function createState(): MyDefState
    {
        $state = new MyDefState();
        $this->states[$state->getId()] = $state;

        return $state;
    }

    public function addState(MyDefState $newstate): void
    {
        $this->states[$newstate->getId()] = $newstate;
    }

    public function getCurrentState(): ?MyDefState
    {
        if (isset($this->blocksIdsStates[$this->blockId])) {
            $stateId = $this->blocksIdsStates[$this->blockId];
            if (isset($this->states[$stateId])) {
                return $this->states[$stateId];
            }
        }

        return null;
    }

    /**
     * @throws LogicException when no state has been assigned to the current block
     */
    public function requireCurrentState(): MyDefState
    {
        return $this->getCurrentState()
            ?? throw new LogicException('the definition has no state for the current block');
    }

    public function getNbStates(): int
    {
        return count($this->states);
    }

    /**
     * @return array<int|string, MyDefState>
     */
    public function getStates(): array
    {
        return $this->states;
    }

    public function getState(int $blockId): ?MyDefState
    {
        if (isset($this->blocksIdsStates[$blockId])) {
            $stateId = $this->blocksIdsStates[$blockId];
            if (isset($this->states[$stateId])) {
                return $this->states[$stateId];
            }
        }

        return null;
    }

    public function setArgToParam(MyDefinition $def): void
    {
        $this->argToParam = $def;
    }

    public function getArgToParam(): ?MyDefinition
    {
        return $this->argToParam;
    }

    public function setParamToArg(?MyDefinition $def): void
    {
        $this->paramToArg = $def;
    }

    public function getParamToArg(): ?MyDefinition
    {
        return $this->paramToArg;
    }

    public function setValidWhenReturning(bool $value): void
    {
        $this->validWhenReturning = $value;
    }

    public function getValidWhenReturning(): bool
    {
        return $this->validWhenReturning;
    }

    public function setValidNotBoolean(bool $value): void
    {
        $this->validNotBoolean = $value;
    }

    public function getValidNotBoolean(): bool
    {
        return $this->validNotBoolean;
    }

    public function setReturnedFromValidator(bool $value): void
    {
        $this->returnedFromValidator = $value;
    }

    public function getReturnedFromValidator(): bool
    {
        return $this->returnedFromValidator;
    }

    public function getClassName(): string
    {
        return $this->className;
    }

    public function setClassName(string $className): void
    {
        $this->className = $className;
    }

    /**
     * @return list<MyDefinition>
     */
    public function getRefs(): array
    {
        return $this->refs;
    }

    /**
     * @param list<MyDefinition> $refs
     */
    public function setRefs(array $refs): void
    {
        $this->refs = $refs;
    }

    /**
     * @return list<MyDefinition>
     */
    public function getIteratorValues(): array
    {
        return $this->iteratorValues;
    }

    /**
     * @param list<MyDefinition> $iteratorValues
     */
    public function setIteratorValues(array $iteratorValues): void
    {
        $this->iteratorValues = $iteratorValues;
    }

    public function getBlockId(): int
    {
        return $this->blockId;
    }

    public function setBlockId(int $blockId): void
    {
        $this->blockId = $blockId;
    }

    public function isReturnDef(): ?bool
    {
        return $this->returnDef;
    }

    public function setReturnDef(bool $returnDef): void
    {
        $this->returnDef = $returnDef;
    }
}
