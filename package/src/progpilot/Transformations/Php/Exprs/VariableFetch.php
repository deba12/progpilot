<?php

/*
 * This file is part of ProgPilot, a static analyzer for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


namespace progpilot\Transformations\Php\Exprs;

use progpilot\Context;
use PHPCfg\Operand\Variable;
use PHPCfg\Operand\Literal;
use progpilot\Objects\MyDefinition;
use progpilot\Code\MyInstruction;
use progpilot\Code\Opcodes;

class VariableFetch
{
    public static function variableFetch(Context $context, mixed $op, ?string $expr): void
    {
        if (
            isset($op->original) && $op->original instanceof Variable
            && isset($op->original->name) && $op->original->name instanceof Literal
        ) {
            $myTemp = new MyDefinition(
                $context->requireCurrentBlock()->getId(),
                $context->getCurrentMyFile(),
                $context->getCurrentLine(),
                $context->getCurrentColumn(),
                $op->original->name->value
            );

            $instVariableFetch = new MyInstruction(Opcodes::VARIABLE_FETCH);

            $property = is_null($expr) ? MyInstruction::VARID : MyInstruction::EXPRID;

            $instVariableFetch->addProperty(
                $property,
                $context->requireCurrentFunc()->getOpId($op)
            );

            $instVariableFetch->addProperty(MyInstruction::DEF, $myTemp);
            $context->requireCurrentMycode()->addCode($instVariableFetch);
        }
    }
}
