<?php

/*
 * This file is part of ProgPilot, a static analyzer for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


namespace progpilot\Transformations\Php;

use progpilot\Context;
use PHPCfg\Operand;
use PHPCfg\Op\Expr\AssignRef;
use PHPCfg\Op;
use progpilot\Objects\MyDefinition;
use progpilot\Objects\MyOp;
use progpilot\Code\MyInstruction;
use progpilot\Code\Opcodes;
use progpilot\Transformations\Php\Common;

class Assign
{
    public static function instruction(
        Context $context,
        Op $op,
        ?Operand $expr,
        ?Operand $var,
        bool $isReturnDef = false,
        bool $isDefine = false
    ): ?MyDefinition {
        $backDef = null;

        if ($isDefine) {
            $name = "const_" . rand();
            if (isset($context->getCurrentOp()->args[0]->value)) {
                $name = $context->getCurrentOp()->args[0]->value;
                $var = $context->getCurrentOp()->args[0];
            }

            if (isset($context->getCurrentOp()->args[1])) {
                $expr = $context->getCurrentOp()->args[1];
            }
        } else {
            $name = Common::getNameDefinition($context->getCurrentOp());
            if (empty($name)) {
                $name = "empty_" . rand();
            }
        }

        // name of function return
        if ($isReturnDef) {
            $name = $context->requireCurrentFunc()->getName() . "_return";
        }

        $instAssign = new MyInstruction(Opcodes::END_ASSIGN);

        // extra = properties, arrays
        // $left(extra) = $right(extra) <= expr right

        // let's start by the right part
        // in case of the expr has not been catched naturally in the transform
        if (isset($expr)) {
            Expr::implicitfetch($context, $expr, null);
        }

        // let's continue by the left part
        $instDefinition = new MyInstruction(Opcodes::DEFINITION);

        $myDef = new MyDefinition(
            $context->requireCurrentBlock()->getId(),
            $context->getCurrentMyFile(),
            $context->getCurrentLine(),
            $context->getCurrentColumn(),
            $name
        );

        switch (Common::getTypeDef($op)) {
            case MyOp::TYPE_ARRAY:
                $myDef->addType(MyDefinition::TYPE_ARRAY);
                $myDef->requireCurrentState()->addType(MyDefinition::TYPE_ARRAY);
                break;
            case MyOp::TYPE_PROPERTY:
                $myDef->addType(MyDefinition::TYPE_PROPERTY);
                break;
            case MyOp::TYPE_STATIC_PROPERTY:
                $myDef->addType(MyDefinition::TYPE_STATIC_PROPERTY);
                break;
            case MyOp::TYPE_CONST:
                $myDef->addType(MyDefinition::TYPE_CONSTANTE);
                break;
            case MyOp::TYPE_VARIABLE:
                break;
            default:
                break;
        }

        $instDefinition->addProperty(MyInstruction::DEF, $myDef);
        $context->requireCurrentMycode()->addCode($instDefinition);

        $instAssign->addProperty(MyInstruction::DEF, $myDef);

        if ($op instanceof AssignRef) {
            $instAssign->addProperty(MyInstruction::REFERENCE, true);
        }

        if ($isReturnDef) {
            $context->requireCurrentFunc()->addReturnDef($myDef);
            $context->requireCurrentBlock()->addReturnDef($myDef);
            $myDef->setReturnDef(true);
        }

        $instAssign->addProperty(
            MyInstruction::EXPRID,
            $context->requireCurrentFunc()->getOpId($expr)
        );

        if (!$isReturnDef) {
            $instAssign->addProperty(
                MyInstruction::VARID,
                $context->requireCurrentFunc()->getOpId($var)
            );
        }

        if (isset($op->result)) {
            $instAssign->addProperty(
                MyInstruction::RESULTID,
                $context->requireCurrentFunc()->getOpId($op->result)
            );
        }

        $context->requireCurrentMycode()->addCode($instAssign);

        return $backDef;
    }
}
