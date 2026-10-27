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
use PHPCfg\Operand;
use progpilot\Objects\MyDefinition;
use progpilot\Code\MyInstruction;
use progpilot\Code\Opcodes;

class LiteralFetch
{
    public static function literalFetch(Context $context, Operand $op): void
    {
        if (
            $op instanceof Literal
        ) {
            $myTemp = new MyDefinition(
                $context->requireCurrentBlock()->getId(),
                $context->getCurrentMyFile(),
                $context->getCurrentLine(),
                $context->getCurrentColumn(),
                "literal"
            );

            $myTemp->requireCurrentState()->addType(MyDefinition::TYPE_LITERAL);
            $myTemp->requireCurrentState()->addLastKnownValue($op->value);

            $instDefChained = new MyInstruction(Opcodes::LITERAL_FETCH);
            $instDefChained->addProperty(MyInstruction::DEF, $myTemp);
            $instDefChained->addProperty(MyInstruction::RESULTID, $context->requireCurrentFunc()->getOpId($op));
            $context->requireCurrentMycode()->addCode($instDefChained);
        }
    }
}
