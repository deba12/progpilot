<?php

/*
 * This file is part of ProgPilot, a static analyzer for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


namespace progpilot\Representations;

use progpilot\Objects\MyBlock;

class ControlFlowGraph
{
    /**
     * @var array<mixed>
     */
    private array $nodes;
    /**
     * @var array<mixed>
     */
    private array $edges;
    /**
     * @var array<string, string>
     */
    private array $myBlockText;

    public function __construct()
    {
        $this->nodes = [];
        $this->edges = [];
        $this->myBlockText = [];
    }

    public function getTextOfMyBlock(int|string $id): string
    {
        if (isset($this->myBlockText["$id"])) {
            return $this->myBlockText["$id"];
        }

        return "";
    }

    public function addTextOfMyBlock(int|string $id, string $text): void
    {
        if (isset($this->myBlockText["$id"])) {
            $this->myBlockText["$id"] = $this->myBlockText["$id"] . "$text";
        } else {
            $this->myBlockText["$id"] = "$text";
        }
    }

    /**
     * @return array<mixed>
     */
    public function getNodes(): array
    {
        return $this->nodes;
    }

    /**
     * @return array<mixed>
     */
    public function getEdges(): array
    {
        return $this->edges;
    }

    public function addNode(int|string $id, mixed $block): void
    {
        $this->nodes["$id"] = $block;
    }

    public function getIdOfNode(mixed $block): int|string
    {
        foreach ($this->nodes as $id => $blockTmp) {
            if ($block === $blockTmp) {
                return $id;
            }
        }

        return -1;
    }

    public function addEdge(MyBlock $caller, MyBlock $callee): void
    {
        $this->edges[] = [$caller, $callee];
    }
}
