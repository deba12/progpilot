<?php

/*
 * This file is part of ProgPilot, a static analyzer for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


namespace progpilot\Helpers;

use progpilot\Objects\MyAssertion;

class Callbacks
{
    public static function modifyMyclassOfObject($context, $idObject, $currentMyclass, $newMyclass): void
    {
        if (!is_null($currentMyclass) && $currentMyclass->getName() === $newMyclass->getName()) {
            $context->getObjects()->addMyclassToObject($idObject, $newMyclass);
        }
    }

    public static function addStateDefAsAPastArgument($myfunc, $nbparam, $arg): void
    {
        $myfunc->addStatePastArgument($nbparam, $arg->getCurrentState());
    }

    public static function addAttributesOfInitialReturnDefs($returnDef, $initialReturnDef): void
    {
        $returnDef->setStates($initialReturnDef->getStates());
        $returnDef->setStatesToBlocksIds($initialReturnDef->getStatesToBlocksIds());
    }

    public static function addSanitizedTypes($defValid, $sanitizedTypes): void
    {
        $defValid->getCurrentState()->setSanitized(true);
        if (is_array($sanitizedTypes)) {
            foreach ($sanitizedTypes as $sanitizedType) {
                $defValid->getCurrentState()->addTypeSanitized($sanitizedType);
            }
        }
    }

    public static function addValidAssertion($defValid, $block): void
    {
        $myAssertion = new MyAssertion($defValid, "valid");
        $block->addAssertion($myAssertion);
    }

    public static function cleanTaintedDef($def, $funcDefs): void
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
