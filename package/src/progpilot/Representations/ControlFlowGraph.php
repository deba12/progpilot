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
    private array $nodes;
    private array $edges;
    private array $myBlockText;

    public function __construct()
    {
        $this->nodes = [];
        $this->edges = [];
        $this->myBlockText = [];
    }

    public function getTextOfMyBlock($id)
    {
        if (isset($this->myBlockText["$id"])) {
            return $this->myBlockText["$id"];
        }

        return "";
    }

    public function addTextOfMyBlock($id, $text): void
    {
        if (isset($this->myBlockText["$id"])) {
            $this->myBlockText["$id"] = $this->myBlockText["$id"] . "$text";
        } else {
            $this->myBlockText["$id"] = "$text";
        }
    }

    public function getNodes(): array
    {
        return $this->nodes;
    }

    public function getEdges(): array
    {
        return $this->edges;
    }

    public function addNode($id, $block): void
    {
        $this->nodes["$id"] = $block;
    }

    public function getIdOfNode($block): int|string
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
