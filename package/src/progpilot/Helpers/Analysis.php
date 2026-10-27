<?php

/*
 * This file is part of ProgPilot, a static analyzer for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


declare(strict_types=1);

namespace progpilot\Helpers;

use progpilot\Context;
use progpilot\Objects\MyFunction;
use progpilot\Code\MyInstruction;
use progpilot\Objects\MyBlock;
use progpilot\Inputs\MyCustomFunction;
use progpilot\Inputs\MyCustomRule;
use progpilot\Objects\MyOp;
use progpilot\Objects\MyDefinition;
use progpilot\Objects\MyClass;

class Analysis
{
    public static function forAllobjects(Context $context, string $func, MyClass $myClass): void
    {
        foreach ($context->getObjects()->getObjects() as $id => $objectClass) {
            $params = array($context, $id, $objectClass, $myClass);
            call_user_func_array(__NAMESPACE__ . "\\$func", $params);
        }
    }

    public static function forDefsInFunctions(Context $context, string $func, ?MyClass $myClass): void
    {
        foreach ($context->getFunctions()->getFunctions() as $functionsBlocks) {
            foreach ($functionsBlocks as $functionBlock) {
                foreach ($functionBlock->getDefs()->getDefs() as $defsBlocks) {
                    foreach ($defsBlocks as $defBlock) {
                        $params = array($context, $defBlock, $myClass);
                        call_user_func_array(__NAMESPACE__ . "\\$func", $params);
                    }
                }
            }
        }
    }

    public static function forAllDefsOfFunctionExceptReturnDefs(string $func, MyFunction $myFunc): void
    {
        $returnDefs = $myFunc->getReturnDefs();
        foreach ($myFunc->getDefs()->getDefs() as $defnames) {
            foreach ($defnames as $def) {
                if (!in_array($def, $returnDefs, true)) {
                    $params = array($def, $myFunc->getDefs());
                    call_user_func_array(__NAMESPACE__ . "\\$func", $params);
                }
            }
        }
    }

    public static function forAllReturnDefsOfFunction(string $func, MyFunction $myFunc): void
    {
        $initialReturnDefs = $myFunc->getInitialReturnDefs();
        $returnDefs = $myFunc->getReturnDefs();
        $i = 0;
        foreach ($returnDefs as $returnDef) {
            if (isset($initialReturnDefs[$i])) {
                $params = array($returnDef, $initialReturnDefs[$i]);
                call_user_func_array(__NAMESPACE__ . "\\$func", $params);
            }

            $i++;
        }
    }

    public static function forAllDefsOfFunction(string $func, MyFunction $myFunc): void
    {
        foreach ($myFunc->getDefs()->getDefs() as $defnames) {
            foreach ($defnames as $def) {
                $params = array($def, $myFunc->getDefs());
                call_user_func_array(__NAMESPACE__ . "\\$func", $params);
            }
        }
    }

    public static function forAllArgumentsOfFunction(string $func, MyFunction $myfunc, MyInstruction $instruction): void
    {
        $params = $myfunc->getParams();

        for ($i = 0; $i < count($params); $i++) {
            if ($instruction->isPropertyExist("argdef$i")) { // myfunccall
                $defArg = $instruction->getProperty("argdef$i");
                $params = array($myfunc, $i, $defArg);
                call_user_func_array(__NAMESPACE__ . "\\$func", $params);
            }
        }
    }

    public static function checkIfTimeExecutionIsAcceptable(Context $context, MyFunction $myFunc): bool
    {
        $threshold1 = $context->getMaxFileAnalysisDuration() / 4; // 7.5 seconds by default
        $threshold2 = $context->getMaxFileAnalysisDuration() / 15; // 2 seconds by defaults
        $lastExecutionTime = $myFunc->getLastExecutionTime();
        $nbExecutions = $myFunc->getNbExecutions();

        if (
            ($nbExecutions >= 1 && $nbExecutions < 5 && $lastExecutionTime >= $threshold1)
            || ($nbExecutions >= 4 && $nbExecutions < 10 && $lastExecutionTime >= $threshold2)
            || $nbExecutions >= 10
        ) {
            return false;
        }

        return true;
    }

    public static function getBytes(string $val): string|int
    {
        $val = trim($val);
        $last = strtolower($val[strlen($val) - 1]);
        if (!is_numeric($last)) {
            $val = (int) substr($val, 0, -1);
            switch ($last) {
                // The 'G' modifier is available since PHP 5.1.0
                case 'g':
                    $val *= 1024;
                    // no break
                case 'm':
                    $val *= 1024;
                    // no break
                case 'k':
                    $val *= 1024;
            }
        }

        return $val;
    }

    public static function isASource(
        Context $context,
        MyDefinition $def,
        ?MyClass $myClass,
        string|int|null $arrayDim
    ): bool {
        $source = $context->inputs->getSourceByName($def, $myClass, $arrayDim);

        if (!is_null($source)) {
            return true;
        }

        return false;
    }

    /**
     * @param MyBlock|array<mixed> $block
     */
    public static function forEachTaintedByDefs(MyDefinition $def, MyBlock|array $block, string $callback): void
    {
        foreach ($def->getStates() as $state) {
            $taintedDefs = $state->getTaintedByDefs();
            foreach ($taintedDefs as $taintedByDef) {
                $taintedDef = $taintedByDef[0];
                $taintedState = $taintedByDef[1];

                $params = array($taintedDef, $block);
                call_user_func_array(__NAMESPACE__ . "\\$callback", $params);
            }
        }
    }

    /**
     * @param array<string, int|bool> $nbChars
     * @param list<string> $arrayChars
     */
    public static function updateNbChars(array &$nbChars, ?string $string, array $arrayChars): void
    {
        foreach ($arrayChars as $char) {
            if (!isset($nbChars[$char])) {
                $nbChars[$char] = 0;
            }
        }

        if (!is_string($string)) {
            return;
        }

        for ($i = 0; $i < strlen($string); $i++) {
            foreach ($arrayChars as $char) {
                if ($string[$i] === $char) {
                    $nbChars[$char]++;
                }
            }
        }
    }

    /**
     * @return int[]
     * @param list<string> $arrayChars
     */
    public static function getNbChars(?string $string, array $arrayChars): array
    {
        $nbChars = [];

        foreach ($arrayChars as $char) {
            $nbChars[$char] = 0;
        }

        if (!is_string($string)) {
            return $nbChars;
        }

        for ($i = 0; $i < strlen($string); $i++) {
            foreach ($arrayChars as $char) {
                if ($string[$i] === $char) {
                    $nbChars[$char]++;
                }
            }
        }

        return $nbChars;
    }

    public static function checkCallStackReachMaxTime(Context $context): bool
    {
        $callStack = $context->getCallStack();
        $endTime = microtime(true);

        foreach ($callStack as $call) {
            $myFunc = $call[0];
            $startTime = $myFunc->getStartExecutionTime();
            $diff = $endTime - $startTime;

            if ($diff > $context->getMaxFileAnalysisDuration()) {
                return true;
            }
        }

        return false;
    }

    public static function checkDeeplyIfDefIsTainted(MyDefinition $def): bool
    {
        $arrayTotal[] = $def;
        $defsToAnalyze[] = $def;
        while (!empty($defsToAnalyze)) {
            $def = array_pop($defsToAnalyze);
            foreach ($def->getStates() as $state) {
                if ($state->isTainted()) {
                    return true;
                }

                foreach ($state->getArrayIndexes() as $arrayElement) {
                    if (
                        $arrayElement->def !== $def
                        && !in_array($arrayElement->def, $defsToAnalyze, true)
                        && !in_array($arrayElement->def, $arrayTotal, true)
                        && count($arrayTotal) < 50
                    ) {
                        $defsToAnalyze[] = $arrayElement->def;
                        $arrayTotal[] = $arrayElement->def;
                    }
                }
            }
        }

        return false;
    }

    public static function checkIfOneFunctionArgumentIsNew(?MyFunction $myFunc, MyInstruction $instruction): bool
    {
        if (is_null($myFunc)) {
            return false;
        }

            $params = $myFunc->getParams();

        if (empty($params)) {
            // if it's not a method and empty params,
            // then we can't have additional tainted return
            return false;
        }

            $statesPastArgs = $myFunc->getStatePastArguments();
        for ($i = 0; $i < count($params); $i++) {
            if ($instruction->isPropertyExist("argdef$i")) {
                $defArg = $instruction->getProperty("argdef$i");

                if (Analysis::checkDeeplyIfDefIsTainted($defArg)) {
                    return true;
                }

                // is there new values to consider ?
                if (isset($statesPastArgs[$i])) {
                    foreach ($statesPastArgs[$i] as $statePastArg) {
                        if (
                            $defArg->requireCurrentState()->getLastKnownValues()
                            !== $statePastArg->getLastKnownValues()
                        ) {
                            return true;
                        }
                    }
                } else {
                    return true;
                }
            }
        }

        return false;
    }

    public static function checkIfFuncEqualMySpecify(
        Context $context,
        MyCustomFunction $mySpecify,
        MyFunction $myFunc,
        ?MyClass $myClass = null
    ): bool {
        if (
            !$mySpecify->isInstance()
            && $mySpecify->getName() === $myFunc->getName()
        ) {
            return true;
        }

        if (
            $mySpecify->isInstance() &&
            !is_null($myClass) &&
            ($myClass->getName() === $mySpecify->getInstanceOfName() ||
                $myClass->getExtendsOf() === $mySpecify->getInstanceOfName())
        ) {
            return true;
        }

        return false;
    }

    public static function checkIfDefEqualDefRule(
        Context $context,
        mixed $defs,
        MyCustomRule $rule,
        MyOp $def,
        ?MyClass $myClass = null
    ): bool {
        $definition = $rule->getDefinition();

        if (
            !$definition->isInstance()
            && $def->getName() === $definition->getName()
        ) {
            return true;
        }

        if (
            $definition->isInstance() &&
            !is_null($myClass) &&
            $def->getName() === $definition->getName() &&
            ($myClass->getName() === $definition->getInstanceOfName() ||
                $myClass->getExtendsOf() === $definition->getInstanceOfName())
        ) {
            return true;
        }

        return false;
    }

    public static function createObject(Context $context, MyDefinition $myDef): void
    {
        if (
            $myDef->isType(MyDefinition::TYPE_INSTANCE)
            || $myDef->requireCurrentState()->isType(MyDefinition::TYPE_INSTANCE)
        ) {
            $idObject = $context->getObjects()->addObject();

            if ($myDef->requireCurrentState()->getObjectId() === -1) {
                $myDef->requireCurrentState()->setObjectId($idObject);
                $myDef->requireCurrentState()->addType(MyDefinition::TYPE_INSTANCE);

                if (!empty($myDef->getClassName())) {
                    $myClass = $context->getClasses()->getMyClass($myDef->getClassName());
                    if (is_null($myClass)) {
                        $myClass = new MyClass(
                            $myDef->getLine(),
                            $myDef->getColumn(),
                            $myDef->getClassName()
                        );
                    } else {
                        $myClass = clone $myClass;
                    }

                    $context->getObjects()->addMyclassToObject($idObject, $myClass);
                }
            }
        }
    }
}
