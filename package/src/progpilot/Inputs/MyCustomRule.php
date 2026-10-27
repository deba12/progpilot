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

    private ?string $action = null;
    private string $type;
    private ?MySpecify $definition = null;
    private ?string $attack = null;
    private ?string $cwe = null;
    private string $descriptionRule;
    private array $sequenceRule;
    private int $currentOrderNumber;
    private ?string $extra = null;

    public function __construct(string $descriptionRule)
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

    public function getExtra(): ?string
    {
        return $this->extra;
    }

    public function setExtra(string $extra): void
    {
        $this->extra = $extra;
    }

    public function getAttack(): ?string
    {
        return $this->attack;
    }

    public function setAttack(string $attack): void
    {
        $this->attack = $attack;
    }

    public function getCwe(): ?string
    {
        return $this->cwe;
    }

    public function setCwe(string $cwe): void
    {
        $this->cwe = $cwe;
    }

    public function getType(): string
    {
        return $this->type;
    }

    public function setType(string $type): void
    {
        $this->type = $type;
    }

    public function getDefinition(): ?MySpecify
    {
        return $this->definition;
    }

    public function setDefinition(?MySpecify $definition): void
    {
        $this->definition = $definition;
    }

    public function getDescription(): string
    {
        return $this->descriptionRule;
    }

    public function setDescription(string $descriptionRule): void
    {
        $this->descriptionRule = $descriptionRule;
    }

    public function getCurrentOrderNumber(): int
    {
        return $this->currentOrderNumber;
    }

    public function setCurrentOrderNumber(int $currentOrderNumber): void
    {
        $this->currentOrderNumber = $currentOrderNumber;
    }

    /**
     * @return list<MyCustomFunction>
     */
    public function getSequence(): array
    {
        return $this->sequenceRule;
    }

    public function addToSequenceWithAction(string $functionName, string $language, string $action): MyCustomFunction
    {
        $this->currentOrderNumber++;
        $myCustomFunction = new MyCustomFunction($functionName, $language, $this->currentOrderNumber);
        $myCustomFunction->setAction($action);
        $this->sequenceRule[] = $myCustomFunction;

        return $myCustomFunction;
    }

    public function addToSequence(string $functionName, string $language): MyCustomFunction
    {
        $this->currentOrderNumber++;
        $myCustomFunction = new MyCustomFunction($functionName, $language, $this->currentOrderNumber);
        $this->sequenceRule[] = $myCustomFunction;

        return $myCustomFunction;
    }

    public function addFunctionDefinition(string $functionName, string $language): MyCustomFunction
    {
        $myCustomFunction = new MyCustomFunction($functionName, $language);
        $this->definition = $myCustomFunction;

        return $myCustomFunction;
    }

    public function addVariableDefinition(string $variableName, string $language): MyCustomVariable
    {
        $myCustomVariable = new MyCustomVariable($variableName, $language);
        $this->definition = $myCustomVariable;

        return $myCustomVariable;
    }

    public function getAction(): ?string
    {
        return $this->action;
    }

    public function setAction(string $action): string
    {
        return $this->action = $action;
    }
}
