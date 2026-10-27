<?php

/*
 * This file is part of ProgPilot, a static analyzer for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


namespace progpilot\Outputs;

use progpilot\Objects\MyFunction;

class MyOutputs extends MyOutputsInternalApi
{
    public function getAst(?MyFunction $myFunc): array
    {
        $nodesjson = [];
        $linksjson = [];

        if (!is_null($myFunc) && isset($this->ast[$myFunc->getId()])) {
            $tmpAst = $this->ast[$myFunc->getId()];

            foreach ($tmpAst->getNodes() as $node) {
                $hash = spl_object_id($node);

                $nodesjson[] = array('name' => get_class($node), 'id' => $hash);
            }

            foreach ($tmpAst->getEdges() as $edge) {
                $caller = $edge[0];
                $callee = $edge[1];

                $hashcaller = spl_object_id($caller);
                $hashcallee = spl_object_id($callee);

                if ($hashcaller !== $hashcallee) {
                    $linksjson[] = array('target' => $hashcallee, 'source' => $hashcaller);
                }
            }
        }

        return array('nodes' => $nodesjson, 'links' => $linksjson);
    }

    public function getCfg(?MyFunction $myFunc): array
    {
        $nodesjson = [];
        $linksjson = [];
        $realNodes = [];

        if (!is_null($myFunc) && isset($this->cfg[$myFunc->getId()])) {
            $tmpCfg = $this->cfg[$myFunc->getId()];

            foreach ($tmpCfg->getNodes() as $id => $node) {
                $realNodes[] = $id;
                $nodesjson[] = array('name' => $tmpCfg->getTextOfMyBlock($id), 'id' => $id);
            }

            foreach ($tmpCfg->getEdges() as $edge) {
                $callerId = $tmpCfg->getIdOfNode($edge[0]);
                $calleeId = $tmpCfg->getIdOfNode($edge[1]);

                if (
                    $callerId !== $calleeId
                    && in_array($callerId, $realNodes, true)
                    && in_array($calleeId, $realNodes, true)
                ) {
                    $linksjson[] = array('source' => $callerId, 'target' => $calleeId);
                }
            }
        }

        return array('nodes' => $nodesjson, 'links' => $linksjson);
    }

    public function getCallGraph(?MyFunction $myFunc): array
    {
        $nodesjson = [];
        $linksjson = [];
        $realNodes = [];

        if (!is_null($myFunc) && isset($this->callgraph[$myFunc->getId()])) {
            $tmpCallgraph = $this->callgraph[$myFunc->getId()];
            $nodes = $tmpCallgraph->getNodes();

            foreach ($nodes as $nodeCaller) {
                $realNodes[] = $nodeCaller->getId();
                $nodesjson[] = array('name' => $nodeCaller->getName(), 'id' => $nodeCaller->getId());
            }

            foreach ($nodes as $key => $nodeCaller) {
                foreach ($nodeCaller->getChildren() as $key => $nodeCalleeId) {
                    $nodeCallee = $nodes[$nodeCalleeId];
                    if (
                        $nodeCaller->getId() !== $nodeCallee->getId()
                        && in_array($nodeCaller->getId(), $realNodes, true)
                        && in_array($nodeCallee->getId(), $realNodes, true)
                    ) {
                        $linksjson[] = array('source' => $nodeCaller->getId(), 'target' => $nodeCallee->getId());
                    }
                }
            }
        }

        return array('nodes' => $nodesjson, 'links' => $linksjson);
    }

    public function setOnAddResult(callable $func): void
    {
        $this->onAddResult = $func;
    }

    public function getOnAddResult(): ?callable
    {
        return $this->onAddResult;
    }

    /**
     * @return list<array<mixed>>
     */
    public function &getResults(): array
    {
        return $this->results;
    }

    public function setIncludeFailuresFile(string $file): void
    {
        $log = true;
        if (empty($file)) {
            $log = false;
        }

        $this->writeIncludeFailures = $log;
        $this->includeFailuresFile = $file;
    }

    public function getIncludeFailuresFile(): ?string
    {
        return $this->includeFailuresFile;
    }

    public function taintedFlow(bool $bool): void
    {
        $this->taintedFlow = $bool;
    }

    public function getTaintedFlow(): bool
    {
        return $this->taintedFlow;
    }

    public function sarifOutput(bool $bool): void
    {
        $this->sarifOutput = $bool;
    }

    public function getSarifOutput(): bool
    {
        return $this->sarifOutput;
    }
}
