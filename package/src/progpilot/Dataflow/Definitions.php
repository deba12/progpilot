<?php

/*
 * This file is part of ProgPilot, a static analyzer for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


namespace progpilot\Dataflow;

use progpilot\Objects\MyBlock;
use progpilot\Objects\MyDefinition;
use progpilot\Objects\MyFunction;

class Definitions
{
    private ?array $in = null;
    private ?array $out = null;
    private ?array $outminuskill = null;
    /** @var array<int, list<MyDefinition>> */
    private array $gen = [];
    /** @var array<int, list<MyDefinition>> */
    private array $kill = [];
    private ?array $originalDefs = null;

    private array $defs;
    private ?MyFunction $currentFunc = null;
    private int $nbDefs;

    public function __construct()
    {
        $this->currentFunc = null;
        $this->nbDefs = 0;
        $this->defs = [];
    }

    public function setNbDefs(int $nbDefs): void
    {
        $this->nbDefs = $nbDefs;
    }

    public function getNbDefs(): int
    {
        return $this->nbDefs;
    }

    public function printAll(): void
    {
        echo "print gen : \n";
        Definitions::printStdout($this->gen);
        echo "\n";

        echo "print kill : \n";
        Definitions::printStdout($this->kill);
        echo "\n";

        echo "print out : \n";
        Definitions::printStdout($this->out);
        echo "\n";

        echo "print out-kill : \n";
        Definitions::printStdout($this->outminuskill);
        echo "\n";

        echo "print in : \n";
        Definitions::printStdout($this->in);
        echo "\n";
    }

    public static function printBlock($defsParam): void
    {
        if (!is_null($defsParam)) {
            foreach ($defsParam as $def) {
                $def->printStdout();
            }
        }
    }

    public static function printStdout($defsParam): void
    {
        if (!is_null($defsParam)) {
            foreach ($defsParam as $blockId => $defs) {
                echo "blockid $blockId\n";

                if (!is_null($defs)) {
                    foreach ($defs as $def) {
                        $def->printStdout();
                    }
                }
            }
        }
    }

    public function createBlock(int $id): void
    {
        $this->in[$id] = [];
        $this->out[$id] = [];
        $this->outminuskill[$id] = [];
        $this->gen[$id] = [];
        $this->kill[$id] = [];
    }

    /* getters and setters */
    /**
     * @return array<string, array<mixed>>
     */
    public function getDefs(): array
    {
        return $this->defs;
    }

    public function getOriginalDef(int $id): ?MyDefinition
    {
        if (isset($this->originalDefs[$id])) {
            return $this->originalDefs[$id];
        }

        return null;
    }

    public function addDef(string $name, MyDefinition $def): void
    {
        $continue = true;

        if (isset($this->defs[$name])) {
            $continue = false;
            if (!in_array($def, $this->defs[$name], true)) {
                $continue = true;
            }
        }

        if ($continue) {
            $this->nbDefs++;
            $this->defs[$name][] = $def;
            $this->originalDefs[$def->getId()] = clone $def;
        }
    }

    public function addIn($block, $def): bool
    {
        if (isset($this->in[$block]) && !in_array($def, $this->in[$block], true)) {
            $this->in[$block][] = $def;
            return true;
        }

        return false;
    }

    public function addOut($block, $def): bool
    {
        if (isset($this->out[$block]) && !in_array($def, $this->out[$block], true)) {
            $this->out[$block][] = $def;
            return true;
        }

        return false;
    }

    public function addGen(int $block, MyDefinition $def): bool
    {
        if (isset($this->gen[$block]) && !in_array($def, $this->gen[$block], true)) {
            $this->gen[$block][] = $def;
            return true;
        }

        return false;
    }

    public function addKill($block, $def): bool
    {
        if (isset($this->kill[$block]) && !in_array($def, $this->kill[$block], true)) {
            $this->kill[$block][] = $def;
            return true;
        }

        return false;
    }

    /**
     * @return list<MyDefinition>|null
     */
    public function getKill(int $block): ?array
    {
        if (isset($this->kill[$block])) {
            return $this->kill[$block];
        }

        return null;
    }

    /**
     * @return list<MyDefinition>|null
     */
    public function getGen(int $block): ?array
    {
        if (isset($this->gen[$block])) {
            return $this->gen[$block];
        }

        return null;
    }

    /**
     * @return list<MyDefinition>|null
     */
    public function getOut(int $block): ?array
    {
        if (isset($this->out[$block])) {
            return $this->out[$block];
        }

        return null;
    }

    /**
     * @return list<MyDefinition>|null
     */
    public function getOutMinusKill(int $block): ?array
    {
        if (isset($this->outminuskill[$block])) {
            return $this->outminuskill[$block];
        }

        return null;
    }

    /**
     * @return list<MyDefinition>|null
     */
    public function getIn(int $block): ?array
    {
        if (isset($this->in[$block])) {
            return $this->in[$block];
        }

        return null;
    }

    public function setKill($block, $kill): void
    {
        $this->kill[$block] = $kill;
    }

    public function setGen($block, $gen): void
    {
        $this->gen[$block] = $gen;
    }

    /**
     * @param list<MyDefinition> $out
     */
    public function setOut(int $block, array $out): void
    {
        $this->out[$block] = $out;
    }

    /**
     * @param list<MyDefinition> $outminuskill
     */
    public function setOutMinusKill(int $block, array $outminuskill): void
    {
        $this->outminuskill[$block] = $outminuskill;
    }

    /**
     * @param list<MyDefinition> $in
     */
    public function setIn(int $block, array $in): void
    {
        $this->in[$block] = $in;
    }

    public function getCurrentFunc(): ?MyFunction
    {
        return $this->currentFunc;
    }

    public function setCurrentFunc(?MyFunction $currentFunc): void
    {
        $this->currentFunc = $currentFunc;
    }

    /**
     * @return list<MyDefinition>|null
     */
    public function getDefRefByName(string $name): ?array
    {
        if (isset($this->defs[$name])) {
            return $this->defs[$name];
        }

        return null;
    }

    // def1 = def, def2 = defsearch inside ResolveDefs function
    public static function defEquality(MyDefinition $def1, MyDefinition $def2): bool
    {
        if ($def1->getName() === $def2->getName()) {
            return true;
        }

        return false;
    }

    // $this->data["gen"][$blockId]
    public function computeKill(int $blockId): void
    {
        foreach ($this->gen[$blockId] as $gen) {
            $tmpdefs = $this->getDefRefByName($gen->getName());
            if (!is_null($tmpdefs)) {
                foreach ($tmpdefs as $def) {
                    if ($this->defEquality($def, $gen)) {
                        if ($def !== $gen && !in_array($def, $this->kill[$blockId], true)) {
                            $this->kill[$blockId][] = $def;
                        }
                    }
                }
            }
        }
    }

    /**
     * @param list<MyBlock> $myBlocks
     */
    public function reachingDefs(array $myBlocks): void
    {
        foreach ($myBlocks as $block) {
            $blockId = $block->getId();
            $this->setOutMinusKill($blockId, $this->getGen($blockId));
            $this->setOut($blockId, $this->getGen($blockId));
        }

        $change = true;

        while ($change) {
            $change = false;

            foreach ($myBlocks as $block) {
                $idcurrent = $block->getId();
                foreach ($block->parents as $idparent => $parent) {
                    $idparent = $parent->getId();

                    if ($idcurrent !== $idparent) {
                        $temp = ArrayMulti::arrayMergeMulti($this->getIn($idcurrent), $this->getOut($idparent));
                        $this->setIn($idcurrent, $temp);

                        $oldout = $this->getOut($idcurrent);

                        $inminus = ArrayMulti::arrayMinusMulti($this->getIn($idcurrent), $this->getKill($idcurrent));
                        $this->setOut($idcurrent, ArrayMulti::arrayMergeMulti($this->getGen($idcurrent), $inminus));

                        $this->setOutMinusKill(
                            $idcurrent,
                            ArrayMulti::arrayMergeMulti($this->getGen($idcurrent), $this->getIn($idcurrent))
                        );

                        if ($this->getOut($idcurrent) !== $oldout) {
                            $change = true;
                        }
                    }
                }
            }
        }
    }
}
