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
use PHPCfg\Operand\Literal;
use PHPCfg\Op;
use progpilot\Objects\MyDefinition;
use progpilot\Code\MyInstruction;
use progpilot\Code\Opcodes;

class ConstFetch
{
    public static function constFetch(Context $context, Op $op): void
    {
        if (
            $op instanceof Op\Expr\ConstFetch
            && isset($op->name)
            && $op->name instanceof Literal
        ) {
            $myTemp = new MyDefinition(
                $context->requireCurrentBlock()->getId(),
                $context->getCurrentMyFile(),
                $context->getCurrentLine(),
                $context->getCurrentColumn(),
                $op->name->value
            );
            $myTemp->requireCurrentState()->addType(MyDefinition::TYPE_CONSTANTE);
            if ($op->name->value === "DIRECTORY_SEPARATOR") {
                $myTemp->requireCurrentState()->addLastKnownValue("/");
            } else {
                $myTemp->requireCurrentState()->addLastKnownValue($op->name->value);
            }

            $instDefChained = new MyInstruction(Opcodes::CONST_FETCH);
            $instDefChained->addProperty(MyInstruction::DEF, $myTemp);
            $instDefChained->addProperty(MyInstruction::RESULTID, $context->requireCurrentFunc()->getOpId($op->result));
            $context->requireCurrentMycode()->addCode($instDefChained);
        }
    }
}
