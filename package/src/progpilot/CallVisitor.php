<?php

/*
 * This file is part of ProgPilot, a static analyzer for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


namespace progpilot;

use PHPCfg\Block;
use PHPCfg\Op;
use PHPCfg\Visitor;
use PHPCfg\Script;
use PHPCfg\Func;

class CallVisitor implements Visitor
{
    private ?Context $context = null;

    public function setContext(Context $context): void
    {
        $this->context = $context;
    }

    public function enterScript(Script $script): void
    {
    }

    public function leaveScript(Script $script): void
    {
    }

    public function leaveFunc(Func $func): void
    {
    }

    public function enterFunc(Func $func): void
    {
    }

    public function enterBlock(Block $block, ?Block $prior = null): void
    {
    }

    public function skipBlock(Block $block, ?Block $prior = null): void
    {
    }

    public function leaveOp(Op $op, Block $block): void
    {
    }

    public function leaveBlock(Block $block, ?Block $prior = null): void
    {
    }

    public function enterOp(Op $op, Block $block): void
    {
        if (isset($op->class->value)) {
            if (strpos($op->class->value, "\\") !== false) {
                preg_match('/(.*)\\\(.*)/', $op->class->value, $matches);
                if (isset($matches[1])) {
                    // and $matches[2] is the name of the class
                    $this->context->addCallToNamespace($matches[1]);
                }
            }
        }
    }
}
