<?php

/*
 * This file is part of ProgPilot, a static analyzer for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


namespace progpilot\Helpers;

use progpilot\Context;
use progpilot\Objects\MyClass;
use progpilot\Objects\MyFunction;
use progpilot\Objects\MyDefinition;
use progpilot\Objects\MyBlock;
use progpilot\Dataflow\Definitions;
use progpilot\Objects\MyAssertion;

class Callbacks
{
    public static function modifyMyclassOfObject(
        Context $context,
        int $idObject,
        ?MyClass $currentMyclass,
        MyClass $newMyclass
    ): void {
        if (!is_null($currentMyclass) && $currentMyclass->getName() === $newMyclass->getName()) {
            $context->getObjects()->addMyclassToObject($idObject, $newMyclass);
        }
    }

    public static function addStateDefAsAPastArgument(MyFunction $myfunc, int $nbparam, MyDefinition $arg): void
    {
        $myfunc->addStatePastArgument($nbparam, $arg->getCurrentState());
    }

    public static function addAttributesOfInitialReturnDefs(
        MyDefinition $returnDef,
        MyDefinition $initialReturnDef
    ): void {
        $returnDef->setStates($initialReturnDef->getStates());
        $returnDef->setStatesToBlocksIds($initialReturnDef->getStatesToBlocksIds());
    }

    /**
     * @param list<string> $sanitizedTypes
     */
    public static function addSanitizedTypes(MyDefinition $defValid, array $sanitizedTypes): void
    {
        $defValid->requireCurrentState()->setSanitized(true);
        foreach ($sanitizedTypes as $sanitizedType) {
            $defValid->requireCurrentState()->addTypeSanitized($sanitizedType);
        }
    }

    public static function addValidAssertion(MyDefinition $defValid, MyBlock $block): void
    {
        $myAssertion = new MyAssertion($defValid, "valid");
        $block->addAssertion($myAssertion);
    }

    public static function cleanTaintedDef(MyDefinition $def, Definitions $funcDefs): void
    {
        $originalDef = $funcDefs->getOriginalDef($def->getId());

        if (!is_null($originalDef)) {
            $originalDefCopy = clone $originalDef;
            $def->setType($originalDefCopy->getType());
            $def->setSourceMyFile($originalDefCopy->getSourceMyFile());
            $def->setName($originalDefCopy->getName());
            $def->setValidWhenReturning($originalDefCopy->getValidWhenReturning());
            $def->setValidNotBoolean($originalDefCopy->getValidNotBoolean());
            $def->setReturnedFromValidator($originalDefCopy->getReturnedFromValidator());
            $def->setClassName($originalDefCopy->getClassName());
            $def->setRefs($originalDefCopy->getRefs());
            $def->setStates($originalDefCopy->getStates());
            $def->setStatesToBlocksIds($originalDefCopy->getStatesToBlocksIds());
        }
    }
}
