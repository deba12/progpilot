<?php

/*
 * This file is part of ProgPilot, a static analyzer for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


namespace progpilot;

use Exception;
use progpilot\Objects\MyDefinition;
use progpilot\Objects\MyFunction;

class Utils
{
    public static function toColumn($code, $pos): float|int
    {
        if ($pos > strlen($code)) {
            return 1;
        }

        $lineStartPos = strrpos($code, "\n", $pos - strlen($code));
        if (false === $lineStartPos) {
            $lineStartPos = -1;
        }
        return $pos - $lineStartPos;
    }

    public static function encodeCharacters(string $string): string
    {
        return htmlentities($string, ENT_QUOTES, 'UTF-8');
    }

    public static function printWarning(Context $context, string $message): void
    {
        if ($context->isDebugMode()) {
            fwrite(STDERR, "progpilot warning: $message\n");
            fwrite(STDERR, "file: '" . $context->requireCurrentMyfile()->getName() . "'\n");

            // sometimes it's called outside of function context
                fwrite(STDERR, "function: '" . $context->requireCurrentFunc()->getName() . "'\n");
        }
    }

    public static function printError($message): never
    {
        throw new Exception($message);
    }

    /**
     * @param list<MyDefinition|string|int>|null $original
     */
    public static function printDefinition(MyDefinition $def, ?array $original = null): string
    {

        $prefix = "\$";
        if ($def->isType(MyDefinition::TYPE_STATIC_PROPERTY)) {
            // oop/simple31.php
            if (
                !is_null($original)
                && !empty($original)
                && $original[0]->isType(MyDefinition::TYPE_STATIC_PROPERTY)
            ) {
                $prefix = "";
            }
        }

        $printableDef = "";
        if (!is_null($original) && !empty($original)) {
            $wasArray = false;
            $wasStatic = false;
            for ($i = 0; $i < count($original); $i++) {
                if ($original[$i] instanceof MyDefinition) {
                    $printableDef .= "$prefix" . Utils::encodeCharacters($original[$i]->getName());
                } elseif (
                    is_numeric($original[$i])
                    || $original[$i] === ']'
                    || $original[$i] === '['
                    || $original[$i] === '->'
                    || $original[$i] === '::'
                ) {
                    // numeric element
                    $printableDef .= $original[$i];

                    $wasArray = false;
                    if ($original[$i] === '[') {
                        $wasArray = true;
                    }

                    $wasStatic = false;
                    if ($original[$i] === '::') {
                        $wasStatic = true;
                    }
                } else {
                    // string element (array, property name)
                    if ($wasArray) {
                        $printableDef .= "\"";
                    }

                    if ($wasStatic) {
                        $printableDef .= "\$";
                    }

                    $printableDef .= Utils::encodeCharacters($original[$i]);

                    if ($wasArray) {
                        $printableDef .= "\"";
                    }
                }
            }
        } else {
            $printableDef = "$prefix" . Utils::encodeCharacters($def->getName());
        }


        return $printableDef;
    }

    public static function printFunction($function): string
    {
        $functionName = "\$";
        if ($function->isType(MyFunction::TYPE_FUNC_METHOD)) {
            $functionName = Utils::encodeCharacters($function->getMyClass()->getName()) . "->";
        }

        $functionName .= Utils::encodeCharacters($function->getName());

        return $functionName;
    }

    public static function printArray($array, &$print): void
    {
        if (is_array($array)) {
            foreach ($array as $index => $value) {
                if (isset($array[$index])) {
                    if (is_string($index)) {
                        $print .= "[\"" . Utils::encodeCharacters((string) $index) . "\"]";
                    } else {
                        $print .= "[" . Utils::encodeCharacters((string) $index) . "]";
                    }

                    Utils::printArray($array[$index], $print);
                }
            }
        }
    }
}
