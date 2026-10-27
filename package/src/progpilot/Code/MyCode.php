<?php

/*
 * This file is part of ProgPilot, a static analyzer for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


namespace progpilot\Code;

class MyCode
{
    /**
     * @var list<MyInstruction>
     */
    private array $code;
    private int $start = 0;
    private int $end = 0;

    public function __construct()
    {
        $this->code = [];
    }

    public function getStart(): int
    {
        return $this->start;
    }

    public function getEnd(): int
    {
        return $this->end;
    }

    public function setStart(int $start): void
    {
        $this->start = $start;
    }

    public function setEnd(int $end): void
    {
        $this->end = $end;
    }

    /**
     * @param list<MyInstruction> $codes
     */
    public function setCodes(array $codes): void
    {
        $this->code = $codes;
    }

    /**
     * @return list<MyInstruction>
     */
    public function getCodes(): array
    {
        return $this->code;
    }

    public function addCode(MyInstruction $code): void
    {
        $this->code[] = $code;
    }

    public function getLastCode(): MyInstruction
    {
        $last_index = count($this->code);
        return $this->code[$last_index - 1];
    }

    public function printStdout(): void
    {
        $index = 0;
        $currentFunc = null;

        do {
            if (isset($this->code[$index])) {
                $instruction = $this->code[$index];
                echo "[$index] ";
                switch ($instruction->getOpcode()) {
                    case Opcodes::ENTER_FUNCTION:
                        echo "Opcodes::ENTER_FUNCTION\n";

                        $myFunc = $instruction->getProperty(MyInstruction::MYFUNC);
                        $currentFunc = $myFunc;
                        echo "name = " . htmlentities($myFunc->getName(), ENT_QUOTES, 'UTF-8') . "\n";
                        break;

                    case Opcodes::CLASSE:
                        echo "Opcodes::CLASSE\n";

                        $myClass = $instruction->getProperty(MyInstruction::MYCLASS);
                        echo "name = " . htmlentities($myClass->getName(), ENT_QUOTES, 'UTF-8') . "\n";
                        break;

                    case Opcodes::ENTER_BLOCK:
                        echo "Opcodes::ENTER_BLOCK\n";

                        $myBlock = $instruction->getProperty(MyInstruction::MYBLOCK);
                        echo "id = " . $myBlock->getId() . "\n";

                        break;

                    case Opcodes::LEAVE_BLOCK:
                        echo "Opcodes::LEAVE_BLOCK\n";

                        $myBlock = $instruction->getProperty(MyInstruction::MYBLOCK);
                        echo "id = " . $myBlock->getId() . "\n";

                        break;

                    case Opcodes::LEAVE_FUNCTION:
                        echo "Opcodes::LEAVE_FUNCTION\n";

                        break;


                    case Opcodes::FUNC_CALL:
                        echo "Opcodes::FUNC_CALL\n";

                        $funcname = htmlentities(
                            $instruction->getProperty(MyInstruction::FUNCNAME),
                            ENT_QUOTES,
                            'UTF-8'
                        );
                        echo "name = $funcname\n";
                        break;

                    case Opcodes::CONCAT_LIST:
                        echo "Opcodes::CONCAT_LIST\n";
                        break;

                    case Opcodes::CONCAT_LEFT:
                        echo "Opcodes::CONCAT_LEFT\n";
                        break;

                    case Opcodes::CONCAT_RIGHT:
                        echo "Opcodes::CONCAT_RIGHT\n";
                        break;

                    case Opcodes::RETURN_FUNCTION:
                        echo "Opcodes::RETURN_FUNCTION\n";
                        break;

                    case Opcodes::START_ASSIGN:
                        echo "Opcodes::START_ASSIGN\n";
                        break;

                    case Opcodes::END_ASSIGN:
                        echo "Opcodes::END_ASSIGN\n";
                        break;

                    case Opcodes::COND_BOOLEAN_NOT:
                        echo "Opcodes::COND_BOOLEAN_NOT\n";
                        break;

                    case Opcodes::COND_START_IF:
                        echo "Opcodes::COND_START_IF\n";
                        break;

                    case Opcodes::DEFINITION:
                        echo "Opcodes::DEFINITION\n";
                        $defname = htmlentities(
                            $instruction->getProperty(MyInstruction::DEF)->getName(),
                            ENT_QUOTES,
                            'UTF-8'
                        );
                        echo "name = $defname\n";

                        $instruction->getProperty(MyInstruction::DEF)->printStdout();

                        break;

                    case Opcodes::PROPERTY_FETCH:
                        echo "Opcodes::PROPERTY_FETCH\n";
                        $propertyName = htmlentities(
                            $instruction->getProperty(MyInstruction::PROPERTY_NAME),
                            ENT_QUOTES,
                            'UTF-8'
                        );
                        echo "property name = $propertyName\n";

                        break;

                    case Opcodes::STATIC_PROPERTY_FETCH:
                        echo "Opcodes::STATIC_PROPERTY_FETCH\n";
                        $propertyName = htmlentities(
                            $instruction->getProperty(MyInstruction::PROPERTY_NAME),
                            ENT_QUOTES,
                            'UTF-8'
                        );
                        echo "property name = $propertyName\n";

                        break;

                    case Opcodes::ARRAYDIM_FETCH:
                        echo "Opcodes::ARRAYDIM_FETCH\n";
                        $varid = $instruction->getProperty(MyInstruction::VARID);
                        $exprid = $instruction->getProperty(MyInstruction::EXPRID);
                        echo "varid = '$varid'\n";
                        echo "exprid = '$exprid'\n";
                        $arrayDim = $instruction->getProperty(MyInstruction::ARRAY_DIM);
                        echo "array dim = $arrayDim\n";

                        break;

                    case Opcodes::VARIABLE_FETCH:
                        echo "Opcodes::VARIABLE_FETCH\n";
                        $varid = $instruction->getProperty(MyInstruction::VARID);
                        $exprid = $instruction->getProperty(MyInstruction::EXPRID);
                        echo "varid = '$varid'\n";
                        echo "exprid = '$exprid'\n";
                        $instruction->getProperty(MyInstruction::DEF)->printStdout();

                        break;

                    case Opcodes::VARIABLE:
                        echo "Opcodes::VARIABLE\n";
                        $variableName = $instruction->getProperty(MyInstruction::VARIABLE_NAME);
                        echo "variable name = $variableName\n";

                        break;

                    case Opcodes::ASSIGN:
                        echo "Opcodes::ASSIGN\n";

                        break;

                    case Opcodes::ARGUMENT:
                        echo "Opcodes::ARGUMENT\n";

                        break;

                    case Opcodes::CAST:
                        echo "Opcodes::CAST\n";

                        break;

                    case Opcodes::CONST_FETCH:
                        echo "Opcodes::CONST_FETCH\n";

                        break;

                    case Opcodes::LITERAL_FETCH:
                        echo "Opcodes::LITERAL_FETCH\n";
                        $def = $instruction->getProperty(MyInstruction::DEF);
                        if (isset($def->requireCurrentState()->getLastKnownValues()[0])) {
                            $literal = $def->requireCurrentState()->getLastKnownValues()[0];
                            echo "literal = $literal\n";
                        }

                        break;

                    case Opcodes::ITERATOR:
                        echo "Opcodes::ITERATOR\n";

                        break;

                    case Opcodes::ARRAY_EXPR:
                        echo "Opcodes::ARRAY_EXPR\n";

                        break;

                    case Opcodes::BINARYOP:
                        echo "Opcodes::BINARYOP\n";

                        break;
                }

                $index = $index + 1;
            }
        } while (isset($this->code[$index]));
    }
}
