<?php

/*
 * This file is part of ProgPilot, a static analyzer for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


namespace progpilot\Transformations\Php\Exprs;

use progpilot\Context;
use PHPCfg\Op\Expr\Include_;
use PHPCfg\Op\Expr\Print_;
use PHPCfg\Op\Terminal\Echo_;
use PHPCfg\Op\Expr\Eval_;
use PHPCfg\Op\Terminal\Exit_;
use PHPCfg\Op\Expr\NsFuncCall;
use PHPCfg\Op\Expr\MethodCall;
use PHPCfg\Op\Expr\StaticCall;
use PHPCfg\Op\Expr\New_;
use PHPCfg\Op;
use progpilot\Transformations\Php\FuncCall;

class FunccallFetch
{
    public static function funccallFetch(Context $context, Op $op): void
    {
        if (
            ($op instanceof Include_
                || $op instanceof Print_
                || $op instanceof Echo_
                || $op instanceof Eval_
                || $op instanceof Exit_
                || $op instanceof Op\Expr\FuncCall
                || $op instanceof NsFuncCall
                || $op instanceof MethodCall
                || $op instanceof StaticCall
                || $op instanceof New_)
        ) {
            $oldOp = $context->getCurrentOp();
            $context->setCurrentOp($op);
            FuncCall::instruction($context);
            $context->setCurrentOp($oldOp);
        }
    }
}
