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
use PHPCfg\Operand\BoundVariable;
use PHPCfg\Op;
use progpilot\Objects\MyDefinition;
use progpilot\Code\MyInstruction;
use progpilot\Code\Opcodes;

class PropertyFetch
{
    public static function propertyFetch(Context $context, Op $op): void
    {
        if (
            $op instanceof Op\Expr\PropertyFetch
            && isset($op->name->value)
        ) {
            $instDefChained = new MyInstruction(Opcodes::PROPERTY_FETCH);
            $instDefChained->addProperty(MyInstruction::PROPERTY_NAME, $op->name->value);

            // beginning of the chain
            if (isset($op->var->original)) {
                $originalDef = new MyDefinition(
                    $context->requireCurrentBlock()->getId(),
                    $context->getCurrentMyFile(),
                    $context->getCurrentLine(),
                    $context->getCurrentColumn(),
                    $op->var->original->name->value
                );
                $originalDef->addType(MyDefinition::TYPE_PROPERTY);

                $instDefChained->addProperty(MyInstruction::ORIGINAL_DEF, $originalDef);
            }

            if (isset($op->var) && $op->var instanceof BoundVariable) {
                $originalDef = new MyDefinition(
                    $context->requireCurrentBlock()->getId(),
                    $context->getCurrentMyFile(),
                    $context->getCurrentLine(),
                    $context->getCurrentColumn(),
                    "this"
                );
                $instDefChained->addProperty(MyInstruction::ORIGINAL_DEF, $originalDef);
            }

            if (isset($op->result)) {
                $instDefChained->addProperty(
                    MyInstruction::RESULTID,
                    $context->requireCurrentFunc()->getOpId($op->result)
                );
            }
            if (isset($op->var)) {
                $instDefChained->addProperty(
                    MyInstruction::VARID,
                    $context->requireCurrentFunc()->getOpId($op->var)
                );
            }

            $context->requireCurrentMycode()->addCode($instDefChained);
        }
    }
}
