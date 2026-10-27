<?php

namespace progpilot\Representations;

use PhpParser\Node;
use PhpParser\NodeVisitorAbstract;

class AbstractSyntaxTree extends NodeVisitorAbstract
{
    private array $nodes;
    private array $edges;

    public function __construct()
    {
        $this->nodes = [];
        $this->edges = [];
    }

    public function getNodes(): array
    {
        return $this->nodes;
    }

    public function getEdges(): array
    {
        return $this->edges;
    }

    public function addNode(object $node): void
    {
        $this->nodes[] = $node;
    }

    public function addEdge(object $caller, object $callee): void
    {
        $this->edges[] = [$caller, $callee];
    }

    public function beforeTraverse(array $nodes)
    {
        return null;
    }

    public function enterNode(Node $node)
    {
        foreach ($node->getSubNodeNames() as $name) {
            $subNode = &$node->$name;

            if (is_object($subNode)) {
                $this->addEdge($node, $subNode);
            }
        }

        return null;
    }

    public function leaveNode(Node $node)
    {
        return null;
    }

    public function afterTraverse(array $nodes)
    {
        return null;
    }
}
