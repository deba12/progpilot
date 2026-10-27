<?php

/*
 * This file is part of ProgPilot, a static analyzer for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


namespace progpilot\Objects;

use progpilot\Code\MyCode;
use PHPCfg\Operand;
use progpilot\Dataflow\Definitions;

class MyFunction extends MyOp
{
    public const TYPE_FUNC_PROPERTY = 0x0001;
    public const TYPE_FUNC_STATIC = 0x0002;
    public const TYPE_FUNC_METHOD = 0x0004;

    private int $lastLine;
    private int $lastColumn;
    private int $firstBlockId;
    /**
     * @var list<int>
     */
    private array $lastBlockIds;

    private int $nbParams;
    private array $args;
    private array $params;
    private array $returnDefs;
    private array $initialReturnDefs;
    private Definitions $defs;
    private ?array $opInformations = null;
    /**
     * @var list<MyBlock>
     */
    private array $blocks;
    private string $visibility;
    private ?MyClass $myClass = null;
    private int $blockId;
    private ?string $nameInstance = null;

    private ?MyDefinition $thisDef = null;
    private string $instanceClassName;

    private bool $thisHasBeenUpdated;
    private bool $isVisited;
    private bool $isVisitedFromInclude;

    private float $startExecutionTime;
    private float $lastExecutionTime;
    private int $nbExecutions;
    private bool $hasGlobalVariables;
    private MyCode $myCode;

    public function __construct($name)
    {
        parent::__construct($name, 0, 0);

        $this->args = [];
        $this->params = [];
        $this->initialReturnDefs = [];
        $this->returnDefs = [];
        $this->visibility = "public";
        $this->myClass = null;
        $this->nameInstance = null;
        $this->thisDef = null;
        $this->instanceClassName = "";
        $this->blockId = 0;
        $this->firstBlockId = 0;
        $this->nbParams = 0;

        $this->lastLine = 0;
        $this->lastColumn = 0;
        $this->lastBlockIds = [];
        $this->lastExecutionTime = 0;
        $this->startExecutionTime = 0;
        $this->nbExecutions = 0;

        $this->thisHasBeenUpdated = false;
        $this->isVisited = false;
        $this->isVisitedFromInclude = false;
        $this->hasGlobalVariables = false;

        $this->defs = new Definitions();
        $this->opInformations = [];
        $this->blocks = [];

        $this->myCode = new MyCode();
    }

    public function reset(): void
    {
        $this->opInformations = [];
    }

    public function setNbExecutions(int $nbExecutions): void
    {
        $this->nbExecutions = $nbExecutions;
    }

    public function getNbExecutions(): int
    {
        return $this->nbExecutions;
    }

    public function setStartExecutionTime(float $startExecutionTime): void
    {
        $this->startExecutionTime = $startExecutionTime;
    }

    public function getStartExecutionTime(): float
    {
        return $this->startExecutionTime;
    }

    public function setLastExecutionTime(float $lastExecutionTime): void
    {
        $this->lastExecutionTime = $lastExecutionTime;
    }

    public function getLastExecutionTime(): float
    {
        return $this->lastExecutionTime;
    }

    public function setThisHasBeenUpdated(bool $thisHasBeenUpdated): void
    {
        $this->thisHasBeenUpdated = $thisHasBeenUpdated;
    }

    public function thisHasBeenUpdated(): bool
    {
        return $this->thisHasBeenUpdated;
    }

    public function setHasGlobalVariables(bool $hasGlobalVariables): void
    {
        $this->hasGlobalVariables = $hasGlobalVariables;
    }

    public function hasGlobalVariables(): bool
    {
        return $this->hasGlobalVariables;
    }

    public function setIsVisitedFromInclude(bool $isVisited): void
    {
        $this->isVisitedFromInclude = $isVisited;
    }

    public function isVisitedFromInclude(): bool
    {
        return $this->isVisitedFromInclude;
    }

    public function setIsVisited(bool $isVisited): void
    {
        $this->isVisited = $isVisited;
    }

    public function isVisited(): bool
    {
        return $this->isVisited;
    }

    public function setMyCode(MyCode $myCode): void
    {
        $this->myCode = $myCode;
    }

    public function getMyCode(): MyCode
    {
        return $this->myCode;
    }

    public function setLastLine(int $lastLine): void
    {
        $this->lastLine = $lastLine;
    }

    public function setLastColumn(int $lastColumn): void
    {
        $this->lastColumn = $lastColumn;
    }

    /**
     * @param list<int> $lastBlockIds
     */
    public function setLastBlockIds(array $lastBlockIds): void
    {
        $this->lastBlockIds = $lastBlockIds;
    }

    /**
     * @return list<int>
     */
    public function getLastBlockIds(): array
    {
        return $this->lastBlockIds;
    }

    public function addLastBlockId(int $id): void
    {
        if (!in_array($id, $this->lastBlockIds, true)) {
            $this->lastBlockIds[] = $id;
        }
    }

    public function getLastLine(): int
    {
        return $this->lastLine;
    }

    public function getLastColumn(): int
    {
        return $this->lastColumn;
    }

    public function getMyClass(): ?MyClass
    {
        return $this->myClass;
    }

    public function setMyClass(MyClass $myClass): void
    {
        $this->myClass = $myClass;
    }

    public function getThisDef(): ?MyDefinition
    {
        return $this->thisDef;
    }

    public function setThisDef(MyDefinition $thisDef): void
    {
        $this->thisDef = $thisDef;
    }

    public function getInstanceClassName(): string
    {
        return $this->instanceClassName;
    }

    public function setInstanceClassName(string $instanceClassName): void
    {
        $this->instanceClassName = $instanceClassName;
    }

    public function getNameInstance(): ?string
    {
        return $this->nameInstance;
    }

    public function setNameInstance(string $nameInstance): void
    {
        $this->nameInstance = $nameInstance;
    }

    public function setVisibility(string $visibility): void
    {
        $this->visibility = $visibility;
    }

    public function getVisibility(): string
    {
        return $this->visibility;
    }

    /**
     * @param list<MyBlock> $blocks
     */
    public function setBlocks(array $blocks): void
    {
        $this->blocks = $blocks;
    }

    /**
     * @return list<MyBlock>
     */
    public function getBlocks(): array
    {
        return $this->blocks;
    }

    public function getBlockById(int $id): ?MyBlock
    {
        foreach ($this->blocks as $block) {
            if ($block->getId() === $id) {
                return $block;
            }
        }

        return null;
    }

    public function setOpInformations(?array $opInformations): void
    {
        $this->opInformations = $opInformations;
    }

    public function getOpInformations(): ?array
    {
        return $this->opInformations;
    }

    public function getOpId(?Operand $op): ?int
    {
        if (is_object($op)) {
            return spl_object_id($op);
        }

        return null;
    }

    public function getNbsOpInformations(): int
    {
        $nb = 0;
        if (is_array($this->opInformations)) {
            foreach ($this->opInformations as $opInformation) {
                if (isset($opInformation["chained_results"])) {
                    $nb += count($opInformation["chained_results"]);
                }

                if (isset($opInformation["valid_when_returning"])) {
                    $nb += 1;
                }

                if (isset($opInformation["condition_defs"])) {
                    $nb += count($opInformation["condition_defs"]);
                }
            }
        }

        return $nb;
    }

    public function cleanOpInformations(): void
    {
        $this->opInformations = null;
    }

    public function cleanOpInformation(?int $id): void
    {
        if (isset($this->opInformations[$id])) {
            unset($this->opInformations[$id]);
        }
    }

    /**
     * @return array<string, array<mixed>|null|MyDefinition|string|int|bool>|null
     */
    public function getOpInformation(?int $id): ?array
    {
        if (isset($this->opInformations[$id])) {
            return $this->opInformations[$id];
        }

        return null;
    }

    /**
     * @param array<string, array<mixed>|null|MyDefinition|string|int|bool>|null $infos
     */
    public function storeOpInformation(?int $id, ?array $infos): void
    {
        if (!empty($id)) {
            $this->opInformations[$id] = $infos;
        }
    }

    public function setDefs(Definitions $defs): void
    {
        $this->defs = $defs;
    }

    public function getDefs(): Definitions
    {
        return $this->defs;
    }

    /**
     * @return list<array<mixed>>
     */
    public function getStatePastArguments(): array
    {
        return $this->args;
    }

    public function addStatePastArgument(mixed $nbparam, MyDefState $state): void
    {
        $this->args[$nbparam][] = $state;
    }

    public function addParam(MyDefinition $param): void
    {
        $this->params[] = $param;
    }

    /**
     * @return list<MyDefinition>
     */
    public function getParams(): array
    {
        return $this->params;
    }

    public function setNbParams(int $nbParams): void
    {
        $this->nbParams = $nbParams;
    }

    public function getNbParams(): int
    {
        return $this->nbParams;
    }

    public function getParam($i): ?MyDefinition
    {
        if (isset($this->params[$i])) {
            return $this->params[$i];
        }

        return null;
    }

    /**
     * @return list<MyDefinition>
     */
    public function getReturnDefs(): array
    {
        return $this->returnDefs;
    }

    public function addReturnDef(MyDefinition $return_def): void
    {
        $this->returnDefs[] = $return_def;
    }

    public function setReturnDefs(array $returndefs): void
    {
        $this->returnDefs = $returndefs;
    }

    /**
     * @return list<MyDefinition>
     */
    public function getInitialReturnDefs(): array
    {
        return $this->initialReturnDefs;
    }

    public function addInitialReturnDef(MyDefinition $returnDef): void
    {
        $this->initialReturnDefs[] = $returnDef;
    }

    public function setInitialReturnDefs(array $returndefs): void
    {
        $this->initialReturnDefs = $returndefs;
    }

    public function getFirstBlockId(): int
    {
        return $this->firstBlockId;
    }

    public function setFirstBlockId(int $blockId): void
    {
        $this->firstBlockId = $blockId;
    }

    public function getBlockId(): int
    {
        return $this->blockId;
    }

    public function setBlockId(int $blockId): void
    {
        $this->blockId = $blockId;
    }
}
