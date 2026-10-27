<?php

/*
 * This file is part of ProgPilot, a static analyzer for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


declare(strict_types=1);

namespace progpilot\Transformations\Php\Exprs;

use progpilot\Context;
use PHPCfg\Op\Expr\Array_;
use PHPCfg\Op;
use progpilot\Code\MyInstruction;
use progpilot\Code\Opcodes;
use progpilot\Transformations\Php\Expr;

class ArrayFetch
{
    public static function arrayFetch(Context $context, Op $op): void
    {
        if (
            $op instanceof Array_
        ) {
            if (isset($op->values) && !empty($op->values)) {
                $instVariableFetch = new MyInstruction(Opcodes::ARRAY_EXPR);
                $nbArrayExpr = 0;
                foreach ($op->values as $value) {
                    if (isset($op->keys[$nbArrayExpr])) {
                        $instVariableFetch->addProperty(
                            "key" . $nbArrayExpr,
                            $context->requireCurrentFunc()->getOpId($op->keys[$nbArrayExpr])
                        );

                        Expr::implicitfetch($context, $op->keys[$nbArrayExpr], "");
                    }

                    Expr::implicitfetch($context, $value, "");
                    $instVariableFetch->addProperty(
                        "value" . $nbArrayExpr,
                        $context->requireCurrentFunc()->getOpId($value)
                    );

                    $nbArrayExpr++;
                }


                $instVariableFetch->addProperty(
                    MyInstruction::RESULTID,
                    $context->requireCurrentFunc()->getOpId($op->result)
                );

                $instVariableFetch->addProperty(
                    "nbkeys",
                    $nbArrayExpr
                );

                $context->requireCurrentMycode()->addCode($instVariableFetch);
            }
        }
    }
}
