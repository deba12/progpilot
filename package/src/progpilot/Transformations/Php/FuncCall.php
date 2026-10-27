<?php

/*
 * This file is part of ProgPilot, a static analyzer for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


declare(strict_types=1);

namespace progpilot\Transformations\Php;

use PHPCfg\Op\Expr\NsFuncCall;
use progpilot\Context;
use PHPCfg\Operand;
use PHPCfg\Op\Expr\MethodCall;
use PHPCfg\Op\Expr\New_;
use PHPCfg\Op\Expr\Include_;
use PHPCfg\Op\Expr\Print_;
use PHPCfg\Op\Terminal\Echo_;
use PHPCfg\Op\Expr\Eval_;
use PHPCfg\Op\Terminal\Exit_;
use PHPCfg\Op\Expr\StaticCall;
use progpilot\Objects\MyFunction;
use progpilot\Objects\MyDefinition;
use progpilot\Code\MyInstruction;
use progpilot\Code\Opcodes;
use progpilot\Transformations\Php\Expr;

class FuncCall
{
    public static function argument(
        Context $context,
        Operand $arg,
        MyInstruction $instFuncCallMain,
        string $funcCallName,
        int $numParam
    ): void {
        Expr::implicitfetch($context, $arg, null);

        $instVariable = $context->requireCurrentMycode()->getLastCode();
        if ($instVariable->getOpcode() === Opcodes::VARIABLE_FETCH) {
            $defArg = $instVariable->getProperty(MyInstruction::DEF);
            $instFuncCallMain->addProperty("argoriginaldef$numParam", $defArg);
        }

        $defName =
            $funcCallName .
            "_param" .
            $numParam .
            "_line" .
            $context->getCurrentLine() .
            "_column" .
            $context->getCurrentColumn() .
            "_progpilot";

        $myDef = new MyDefinition(
            $context->requireCurrentBlock()->getId(),
            $context->getCurrentMyFile(),
            $context->getCurrentLine(),
            $context->getCurrentColumn(),
            $defName
        );


        $instArg = new MyInstruction(Opcodes::ARGUMENT);
        $instArg->addProperty(MyInstruction::VARID, $context->requireCurrentFunc()->getOpId($arg));
        $context->requireCurrentMycode()->addCode($instArg);

        $instArg->addProperty("argdef$numParam", $myDef);
        $instArg->addProperty("idparam", $numParam);

        $instFuncCallMain->addProperty("argdef$numParam", $myDef);
    }

    /*
    arg2 : expr for the return
    arg3 : arr for the return : function_call()[0] (arr = [0])
     */
    public static function instruction(Context $context): void
    {
        $isMethod = false;
        $nbparams = 0;
        $className = "";

        // instance_name = new obj; instance_name->method_name()

        if ($context->getCurrentOp() instanceof MethodCall) {
            $isMethod = true;
            $instanceName = Common::getNameDefinition($context->getCurrentOp()->var);
        }

        $funcCallName = "";
        if ($context->getCurrentOp() instanceof New_) {
            $funcCallName = "__construct";

            if (isset($context->getCurrentOp()->class->value)) {
                $className = $context->getCurrentOp()->class->value;
            }

            if (isset($context->getCurrentOp()->result->usages[0])) {
                $isMethod = true;
                $instanceName = Common::getNameDefinition($context->getCurrentOp()->result->usages[0]);
            }
        } elseif (isset($context->getCurrentOp()->nsName->value)) {
            $funcCallName = $context->getCurrentOp()->nsName->value;
        } elseif (isset($context->getCurrentOp()->name->value)) {
            $funcCallName = $context->getCurrentOp()->name->value;
        }

        if ($funcCallName === "define") {
            Assign::instruction($context, $context->getCurrentOp(), null, null, false, true);
        }

        if ($context->getCurrentOp() instanceof Include_) {
            $funcCallName = "include";
        } elseif ($context->getCurrentOp() instanceof Print_) {
            $funcCallName = "print";
        } elseif ($context->getCurrentOp() instanceof Echo_) {
            $funcCallName = "echo";
        } elseif ($context->getCurrentOp() instanceof Eval_) {
            $funcCallName = "eval";
        } elseif ($context->getCurrentOp() instanceof Exit_) {
            $funcCallName = "exit";
        }

        $instFuncCallMain = new MyInstruction(Opcodes::FUNC_CALL);

        if (isset($context->getCurrentOp()->result)) {
            $instFuncCallMain->addProperty(
                MyInstruction::RESULTID,
                $context->requireCurrentFunc()->getOpId($context->getCurrentOp()->result)
            );
        }
        if (isset($context->getCurrentOp()->var)) {
            $instFuncCallMain->addProperty(
                MyInstruction::VARID,
                $context->requireCurrentFunc()->getOpId($context->getCurrentOp()->var)
            );
        } elseif (isset($context->getCurrentOp()->class)) {
            $instFuncCallMain->addProperty(
                MyInstruction::VARID,
                $context->requireCurrentFunc()->getOpId($context->getCurrentOp()->class)
            );
        }
        $instFuncCallMain->addProperty(MyInstruction::FUNCNAME, $funcCallName);

        $myFunctionCall = new MyFunction($funcCallName);
        $myFunctionCall->setLine($context->getCurrentLine());
        $myFunctionCall->setColumn($context->getCurrentColumn());
        $myFunctionCall->setInstanceClassName($className);

        if (
            $context->getCurrentOp() instanceof StaticCall &&
            isset($context->getCurrentOp()->class->value)
        ) {
            $nameClass = $context->getCurrentOp()->class->value;
            $myFunctionCall->addType(MyFunction::TYPE_FUNC_STATIC);
            $myFunctionCall->setNameInstance($nameClass);
        }

        if ($isMethod) {
            $myFunctionCall->addType(MyFunction::TYPE_FUNC_METHOD);
            $myFunctionCall->setNameInstance($instanceName);
        }

        $listArgs = [];

        if (
            $context->getCurrentOp() instanceof Include_
            || $context->getCurrentOp() instanceof Print_
            || $context->getCurrentOp() instanceof Echo_
            || $context->getCurrentOp() instanceof Eval_
            || $context->getCurrentOp() instanceof Exit_
        ) {
            if (isset($context->getCurrentOp()->expr)) {
                $listArgs[] = $context->getCurrentOp()->expr;
            }

            if ($context->getCurrentOp() instanceof Include_) {
                $instFuncCallMain->addProperty(MyInstruction::TYPE_INCLUDE, $context->getCurrentOp()->type);
            }
        } else {
            $currentOp = $context->getCurrentOp();
            if (
                $currentOp instanceof \PHPCfg\Op\Expr\FuncCall
                || $currentOp instanceof NsFuncCall
                || $currentOp instanceof MethodCall
                || $currentOp instanceof StaticCall
                || $currentOp instanceof New_
            ) {
                $listArgs = $currentOp->args;
            }
        }

        foreach ($listArgs as $arg) {
            FuncCall::argument($context, $arg, $instFuncCallMain, $funcCallName, $nbparams);
            $nbparams++;
        }

        $myFunctionCall->setNbParams($nbparams);
        $instFuncCallMain->addProperty(MyInstruction::MYFUNC_CALL, $myFunctionCall);
        $context->requireCurrentMycode()->addCode($instFuncCallMain);
    }
}
