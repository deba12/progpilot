<?php

namespace progpilot\Representations;

use PhpParser\Node;
use PhpParser\NodeVisitorAbstract;

class AbstractSyntaxTree extends NodeVisitorAbstract
{
    /**
     * @var list<object>
     */
    private array $nodes;
    /**
     * @var list<array{object, object}>
     */
    private array $edges;

    public function __construct()
    {
        $this->nodes = [];
        $this->edges = [];
    }

    /**
     * @return list<object>
     */
    public function getNodes(): array
    {
        return $this->nodes;
    }

    /**
     * @return list<array{object, object}>
     */
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

    #[\Override]
    public function beforeTraverse(array $nodes)
    {
        return null;
    }

    #[\Override]
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

    #[\Override]
    public function leaveNode(Node $node)
    {
        return null;
    }

    #[\Override]
    public function afterTraverse(array $nodes)
    {
        return null;
    }
}
