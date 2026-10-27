<?php

/*
 * This file is part of ProgPilot, a static analyzer for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


declare(strict_types=1);

namespace progpilot\Outputs;

use progpilot\Objects\MyFile;
use progpilot\Objects\MyFunction;
use progpilot\Objects\MyBlock;
use progpilot\Objects\MyClass;
use progpilot\Representations\Callgraph;
use progpilot\Representations\ControlFlowGraph;
use progpilot\Representations\AbstractSyntaxTree;

class MyOutputsInternalApi
{
    /**
     * @var list<array<string, mixed>>
     */
    protected array $results;
    protected bool $writeIncludeFailures;
    protected ?string $includeFailuresFile = null;
    /** @var callable|null */
    protected $onAddResult = null;
    protected bool $taintedFlow;
    protected bool $sarifOutput;
    protected int $countfilesanalyzed;

    /**
     * @var list<MyFile>
     */
    public array $currentIncludesFile;
    /**
     * @var array<int|string, ControlFlowGraph>
     */
    public array $cfg;
    /**
     * @var array<int|string, Callgraph>
     */
    public array $callgraph;
    /**
     * @var array<int|string, AbstractSyntaxTree>
     */
    public array $ast;

    public function __construct()
    {
        $this->writeIncludeFailures = false;
        $this->includeFailuresFile = null;
        $this->currentIncludesFile = [];
        $this->results = [];
        $this->taintedFlow = false;
        $this->sarifOutput = false;
        $this->onAddResult = null;
        $this->countfilesanalyzed = 0;

        $this->cfg = [];
        $this->callgraph = [];
        $this->ast = [];
    }

    public function resetRepresentationsForAllFunctions(): void
    {
        $this->cfg = [];
        $this->callgraph = [];
        $this->ast = [];
    }

    public function createRepresentationsForFunction(?MyFunction $myFunc): void
    {
        if (is_null($myFunc)) {
            return;
        }

            $this->cfg[$myFunc->getId()] = new ControlFlowGraph();
            $this->callgraph[$myFunc->getId()] = new Callgraph();
            $this->ast[$myFunc->getId()] = new AbstractSyntaxTree();
    }

    // cfg accessors
    public function cfgAddTextOfMyBlock(?MyFunction $myFunc, string $id, string $text): void
    {
        if (!is_null($myFunc) && isset($this->cfg[$myFunc->getId()])) {
            $tmpCfg = $this->cfg[$myFunc->getId()];
            $tmpCfg->addTextOfMyBlock($id, $text);
        }
    }

    public function cfgAddNode(?MyFunction $myFunc, string $id, MyBlock $block): void
    {
        if (!is_null($myFunc) && isset($this->cfg[$myFunc->getId()])) {
            $tmpCfg = $this->cfg[$myFunc->getId()];
            $tmpCfg->addNode($id, $block->getStartAddressBlock());
        }
    }

    public function cfgAddEdge(?MyFunction $myFunc, MyBlock $caller, MyBlock $callee): void
    {
        if (!is_null($myFunc) && isset($this->cfg[$myFunc->getId()])) {
            $tmpCfg = $this->cfg[$myFunc->getId()];
            $tmpCfg->addEdge($caller, $callee);
        }
    }

    // callgraph accessors
    public function callgraphAddNode(?MyFunction $myFunc, MyFunction $myFunccall, ?MyClass $myClass): void
    {
        if (!is_null($myFunc) && isset($this->callgraph[$myFunc->getId()])) {
            $tmpCallgraph = $this->callgraph[$myFunc->getId()];
            $tmpCallgraph->addNode($myFunccall, $myClass);
        }
    }

    public function callgraphAddEdge(
        ?MyFunction $myFunc,
        MyFunction $myFuncCaller,
        ?MyClass $myClassCaller,
        MyFunction $myFuncCallee,
        ?MyClass $myClassCallee
    ): void {
        if (!is_null($myFunc) && isset($this->callgraph[$myFunc->getId()])) {
            $tmpCallgraph = $this->callgraph[$myFunc->getId()];
            $tmpCallgraph->addEdge($myFuncCaller, $myClassCaller, $myFuncCallee, $myClassCallee);
        }
    }

    public function callgraphAddFuncCall(
        ?MyFunction $myFunc,
        MyBlock $myBlock,
        MyFunction $myFunccall,
        ?MyClass $myClass
    ): void {
        if (
            !is_null($myFunc)
            && isset($this->callgraph[$myFunc->getId()])
        ) {
            $tmpCallgraph = $this->callgraph[$myFunc->getId()];
            $tmpCallgraph->addFuncCall($myBlock, $myFunccall, $myClass);
        }
    }

    public function callgraphAddChild(?MyFunction $myFunc, MyBlock $myBlockParent, MyBlock $myBlockChild): void
    {
        if (!is_null($myFunc) && isset($this->callgraph[$myFunc->getId()])) {
            $tmpCallgraph = $this->callgraph[$myFunc->getId()];
            $tmpCallgraph->addChild($myBlockParent, $myBlockChild);
        }
    }

    /**
     * @param array<string, array<mixed>|string|int> $temp
     */
    public function addResult(array $temp): void
    {
        if (!in_array($temp, $this->results, true)) {
            if (!is_null($this->onAddResult)) {
                $params = array($temp);
                call_user_func($this->onAddResult, $params);
            }

            $this->results[] = $temp;
        }
    }

    /**
     * @param list<array<mixed>> $results
     */
    public function setResults(array &$results): void
    {
        $this->results = &$results;
    }

    public function getCountAnalyzedFiles(): int
    {
        return $this->countfilesanalyzed;
    }

    public function setCountAnalyzedFiles(int $nb): void
    {
        $this->countfilesanalyzed = $nb;
    }

    public function getWriteIncludeFailures(): bool
    {
        return $this->writeIncludeFailures;
    }

    public function setWriteIncludeFailures(bool $writeIncludeFailures): void
    {
        $this->writeIncludeFailures = $writeIncludeFailures;
    }

    public function writeIncludesFile(): void
    {
        if ($this->writeIncludeFailures) {
            $fp = fopen($this->includeFailuresFile, "w");
            if ($fp) {
                $myArray = "";
                if (count($this->currentIncludesFile) > 0) {
                    $myArray = [];
                    foreach ($this->currentIncludesFile as $includeFile) {
                        $myArray[] = [$includeFile->getName(), $includeFile->getLine(), $includeFile->getColumn()];
                    }
                }

                $outputjson = array('include_failures' => $myArray);
                fwrite($fp, json_encode($outputjson, JSON_UNESCAPED_SLASHES));
                fclose($fp);
            }
        }
    }
}
