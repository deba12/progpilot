<?php

/*
 * This file is part of ProgPilot, a static analyzer for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


namespace progpilot\Inputs;

class MyCustomRule
{
    public const TYPE_FUNCTION = "function";
    public const TYPE_VARIABLE = "variable";
    public const TYPE_SEQUENCE = "sequence";

    private $action;
    private string $type;
    private $definition;
    private $attack;
    private $cwe;
    private $descriptionRule;
    private array $sequenceRule;
    private int $currentOrderNumber;
    private $extra;

    public function __construct($descriptionRule)
    {
        $this->action = null;
        $this->type = MyCustomRule::TYPE_FUNCTION;
        $this->descriptionRule = $descriptionRule;
        $this->sequenceRule = [];
        $this->currentOrderNumber = 0;
        $this->definition = null;
        $this->attack = null;
        $this->cwe = null;
        $this->extra = null;
    }

    public function getExtra()
    {
        return $this->extra;
    }

    public function setExtra($extra): void
    {
        $this->extra = $extra;
    }

    public function getAttack()
    {
        return $this->attack;
    }

    public function setAttack($attack): void
    {
        $this->attack = $attack;
    }

    public function getCwe()
    {
        return $this->cwe;
    }

    public function setCwe($cwe): void
    {
        $this->cwe = $cwe;
    }

    public function getType()
    {
        return $this->type;
    }

    public function setType($type): void
    {
        $this->type = $type;
    }

    public function getDefinition()
    {
        return $this->definition;
    }

    public function setDefinition($definition): void
    {
        $this->definition = $definition;
    }

    public function getDescription()
    {
        return $this->descriptionRule;
    }

    public function setDescription($descriptionRule): void
    {
        $this->descriptionRule = $descriptionRule;
    }

    public function getCurrentOrderNumber()
    {
        return $this->currentOrderNumber;
    }

    public function setCurrentOrderNumber($currentOrderNumber): void
    {
        $this->currentOrderNumber = $currentOrderNumber;
    }

    public function getSequence()
    {
        return $this->sequenceRule;
    }

    public function addToSequenceWithAction($functionName, $language, $action): \progpilot\Inputs\MyCustomFunction
    {
        $this->currentOrderNumber++;
        $myCustomFunction = new MyCustomFunction($functionName, $language, $this->currentOrderNumber);
        $myCustomFunction->setAction($action);
        $this->sequenceRule[] = $myCustomFunction;

        return $myCustomFunction;
    }

    public function addToSequence($functionName, $language): \progpilot\Inputs\MyCustomFunction
    {
        $this->currentOrderNumber++;
        $myCustomFunction = new MyCustomFunction($functionName, $language, $this->currentOrderNumber);
        $this->sequenceRule[] = $myCustomFunction;

        return $myCustomFunction;
    }

    public function addFunctionDefinition($functionName, $language): \progpilot\Inputs\MyCustomFunction
    {
        $myCustomFunction = new MyCustomFunction($functionName, $language);
        $this->definition = $myCustomFunction;

        return $myCustomFunction;
    }

    public function addVariableDefinition($variableName, $language): \progpilot\Inputs\MyCustomVariable
    {
        $myCustomVariable = new MyCustomVariable($variableName, $language);
        $this->definition = $myCustomVariable;

        return $myCustomVariable;
    }

    public function getAction()
    {
        return $this->action;
    }

    public function setAction($action)
    {
        return $this->action = $action;
    }
}
