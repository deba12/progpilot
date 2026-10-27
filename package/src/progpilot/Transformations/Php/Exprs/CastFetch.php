<?php

/*
 * This file is part of ProgPilot, a static analyzer for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


namespace progpilot\Transformations\Php\Exprs;

use progpilot\Context;
use PHPCfg\Op\Expr\Cast\Int_;
use PHPCfg\Op\Expr\Cast\Array_;
use PHPCfg\Op\Expr\Cast\Bool_;
use PHPCfg\Op\Expr\Cast\Double;
use PHPCfg\Op\Expr\Cast\Object_;
use PHPCfg\Op\Expr\Cast\String_;
use PHPCfg\Op;
use progpilot\Transformations\Php\Expr;
use progpilot\Objects\MyDefinition;
use progpilot\Code\MyInstruction;
use progpilot\Code\Opcodes;

class CastFetch
{
    public static function castFetch(Context $context, Op $op, ?string $expr): void
    {
        if (
                $op instanceof Int_
                || $op instanceof Array_
                || $op instanceof Bool_
                || $op instanceof Double
                || $op instanceof Object_
        ) {
            Expr::implicitfetch($context, $op->expr, $expr);
            $instDefChained = new MyInstruction(Opcodes::CAST);
            $instDefChained->addProperty("type_cast", MyDefinition::CAST_SAFE);
            $instDefChained->addProperty(MyInstruction::EXPRID, $context->requireCurrentFunc()->getOpId($op->expr));
            $instDefChained->addProperty(MyInstruction::RESULTID, $context->requireCurrentFunc()->getOpId($op->result));
            $context->requireCurrentMycode()->addCode($instDefChained);
        } elseif ($op instanceof String_) {
            Expr::implicitfetch($context, $op->expr, $expr);
            $instDefChained = new MyInstruction(Opcodes::CAST);
            $instDefChained->addProperty("type_cast", MyDefinition::CAST_NOT_SAFE);
            $instDefChained->addProperty(MyInstruction::EXPRID, $context->requireCurrentFunc()->getOpId($op->expr));
            $instDefChained->addProperty(MyInstruction::RESULTID, $context->requireCurrentFunc()->getOpId($op->result));
            $context->requireCurrentMycode()->addCode($instDefChained);
        }
    }
}
