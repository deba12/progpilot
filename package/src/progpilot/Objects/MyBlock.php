<?php

/*
 * This file is part of ProgPilot, a static analyzer for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


namespace progpilot\Objects;

class MyBlock extends MyOp
{
    private array $returnDefs;
    private int $startAddressBlock;
    private int $endAddressBlock;
    private bool $needUpdateOfState;
    private bool $hasBeenAnalyzed;
    private array $loopParents;

    public array $children;
    public array $parents;
    /**
     * @var list<MyBlock>
     */
    public array $virtualParents;
    public array $assertions;

    public function __construct($startLine, $startColumn)
    {
        parent::__construct("", $startLine, $startColumn);

        $this->returnDefs = [];
        $this->startAddressBlock = -1;
        $this->endAddressBlock = -1;
        $this->assertions = [];
        $this->parents = [];
        $this->loopParents = [];
        $this->virtualParents = [];
        $this->children = [];
        $this->needUpdateOfState = true;
        $this->hasBeenAnalyzed = false;
    }

    public function hasBeenAnalyzed(): bool
    {
        return $this->hasBeenAnalyzed;
    }

    public function setHasBeenAnalyzed(bool $hasBeenAnalyzed): void
    {
        $this->hasBeenAnalyzed = $hasBeenAnalyzed;
    }

    public function setNeedUpdateOfState(bool $update): void
    {
        $this->needUpdateOfState = $update;
    }

    public function doNeedUpdateOfState(): bool
    {
        return $this->needUpdateOfState;
    }

    public function addLoopParent(MyBlock $parent): void
    {
        if (!in_array($parent, $this->loopParents, true)) {
            $this->loopParents[] = $parent;
        }
    }

    public function isLoopParent(MyBlock $parent): bool
    {
        return in_array($parent, $this->loopParents, true);
    }

    public function addVirtualParent(MyBlock $parent): void
    {
        if (!in_array($parent, $this->virtualParents, true)) {
            $this->virtualParents[] = $parent;
        }
    }

    /**
     * @param list<MyBlock> $parents
     */
    public function setVirtualParents(array $parents): void
    {
        $this->virtualParents = $parents;
    }

    /**
     * @return list<MyBlock>
     */
    public function getVirtualParents(): array
    {
        return $this->virtualParents;
    }

    public function addParent(MyBlock $parent): void
    {
        if (!in_array($parent, $this->parents, true)) {
            $this->parents[] = $parent;
        }
    }

    /**
     * @return list<MyBlock>
     */
    public function getParents(): array
    {
        return $this->parents;
    }

    public function addChild(MyBlock $child): void
    {
        if (!in_array($child, $this->children, true)) {
            $this->children[] = $child;
        }
    }

    public function getChildren(): array
    {
        return $this->children;
    }

    public function addReturnDef(MyDefinition $def): void
    {
        if (!in_array($def, $this->returnDefs, true)) {
            $this->returnDefs[] = $def;
        }
    }

    /**
     * @return list<MyDefinition>
     */
    public function getReturnDefs(): array
    {
        return $this->returnDefs;
    }

    public function addAssertion(MyAssertion $myassertion): void
    {
        if (!in_array($myassertion, $this->assertions, true)) {
            $this->assertions[] = $myassertion;
        }
    }

    /**
     * @return list<MyAssertion>
     */
    public function getAssertions(): array
    {
        return $this->assertions;
    }

    public function setStartAddressBlock(int $address): void
    {
        $this->startAddressBlock = $address;
    }

    public function setEndAddressBlock(int $address): void
    {
        $this->endAddressBlock = $address;
    }

    public function getStartAddressBlock(): int
    {
        return $this->startAddressBlock;
    }

    public function getEndAddressBlock(): int
    {
        return $this->endAddressBlock;
    }
}
