<?php

/*
 * This file is part of ProgPilot, a static analyzer for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


declare(strict_types=1);

namespace progpilot\Transformations\Php;

use SplObjectStorage;
use progpilot\Context;
use PHPCfg\Op\Expr\Include_;
use PHPCfg\Op\Stmt;
use PHPCfg\Op\Expr\Assertion;
use PHPCfg\Op\Terminal;
use PHPCfg\Op\Expr\BinaryOp;
use PHPCfg\Op\Expr\BinaryOp\Concat;
use PHPCfg\Op\Expr\BooleanNot;
use PHPCfg\Op\Stmt\JumpIf;
use PHPCfg\Op\Iterator\Value;
use PHPCfg\Op\Terminal\GlobalVar;
use PHPCfg\Op\Terminal\Return_;
use PHPCfg\Op\Expr\AssignRef;
use PHPCfg\Op\Stmt\Class_;
use PHPCfg\Op\Stmt\Property;
use PHPCfg\Block;
use PHPCfg\Func;
use PHPCfg\Op;
use PHPCfg\Script;
use PHPCfg\Visitor;
use PHPCfg\Operand;
use progpilot\Objects\MyFunction;
use progpilot\Objects\MyBlock;
use progpilot\Objects\MyDefinition;
use progpilot\Objects\MyProperty;
use progpilot\Objects\MyClass;
use progpilot\Code\MyInstruction;
use progpilot\Code\Opcodes;
use progpilot\Transformations\Php\Expr;
use progpilot\Transformations\Php\Assign;
use progpilot\Transformations\Php\Common;

class Transform implements Visitor
{
    /**
     * @var list<MyBlock>
     */
    private array $blocksStack;
    /** @var SplObjectStorage<object, MyBlock> */
    private SplObjectStorage $sBlocks;
    private ?Context $context = null;
    /**
     * @var array<mixed>
     */
    private array $blockIfToBeResolved;
    private ?bool $insideInclude = null;
    /** @var SplObjectStorage<Operand, int> */
    private SplObjectStorage $varIds;

    protected function getVarId(Operand $var): int|float
    {
        if (isset($this->varIds[$var])) {
            return $this->varIds[$var];
        }

        return $this->varIds[$var] = $this->varIds->count() + 1;
    }

    public function __construct()
    {
        $this->varIds = new SplObjectStorage();
        $this->sBlocks = new SplObjectStorage();
        $this->blockIfToBeResolved = [];
        $this->blocksStack = [];
    }

    public function setContext(Context $context): void
    {
        $this->context = $context;
    }

    #[\Override]
    public function enterScript(Script $script): void
    {
        $this->context->outputs->currentIncludesFile = [];
    }

    public function checkIsALoop(Block $block, Block $blockToLook): bool
    {
        $allBlocks = [];
        $allBlocks[] = $block;
        $parentsBlocks = [];
        $parentsBlocks[] = $block;
        $myBlockIf = $this->sBlocks[$blockToLook];

        while (!empty($parentsBlocks)) {
            $blockP = array_pop($parentsBlocks);
            if ($this->sBlocks->offsetExists($blockP)) {
                $myBlockP = $this->sBlocks[$blockP];
                foreach ($blockP->parents as $block_parent) {
                    if ($block_parent !== $blockP) {
                        if ($block_parent === $blockToLook) {
                            $myBlockP->addLoopParent($myBlockIf);
                            return true;
                        }

                        if (
                            !in_array($block_parent, $parentsBlocks, true)
                            && !in_array($block_parent, $allBlocks, true)
                        ) {
                            $parentsBlocks[] = $block_parent;
                            $allBlocks[] = $block_parent;
                        }
                    }
                }
            }
        }

        return false;
    }

    #[\Override]
    public function leaveScript(Script $script): void
    {
        foreach ($this->blockIfToBeResolved as $blockResolved) {
            $instructionIf = $blockResolved[0];
            $blockInit = $blockResolved[1];
            $blockIf = $blockResolved[2];
            $blockElse = $blockResolved[3];

            if (
                $this->sBlocks->offsetExists($blockIf)
                && $this->sBlocks->offsetExists($blockElse)
                && $this->sBlocks->offsetExists($blockInit)
            ) {
                $myBlockIf = $this->sBlocks[$blockIf];
                $myBlockElse = $this->sBlocks[$blockElse];
                $myBlockInit = $this->sBlocks[$blockInit];

                if ($this->checkIsALoop($blockInit, $blockIf)) {
                    $myBlockElse->addParent($myBlockIf);
                    $myBlockElse->addVirtualParent($myBlockIf);
                }

                $instructionIf->addProperty(MyInstruction::MYBLOCK_IF, $myBlockIf);
                $instructionIf->addProperty(MyInstruction::MYBLOCK_ELSE, $myBlockElse);
            }
        }

        // creating edges for myblocks structure as block structure
        foreach ($this->sBlocks as $block) {
            $myBlock = $this->sBlocks[$block];
            foreach ($block->parents as $block_parent) {
                if ($this->sBlocks->offsetExists($block_parent)) {
                    $myBlockParent = $this->sBlocks[$block_parent];
                    $myBlock->addParent($myBlockParent);
                    $myBlock->addVirtualParent($myBlockParent);

                    $myBlockParent->addChild($myBlock);
                }
            }
        }

        // extends class
        foreach ($this->context->getClasses()->getListClasses() as $myClass) {
            if (!is_null($myClass->getExtendsOf())) {
                $myClassFather = $this->context->getClasses()->getMyClass($myClass->getExtendsOf());
                if (!is_null($myClassFather)) {
                    foreach ($myClassFather->getMethods() as $methodFather) {
                        $cloneMethodFather = $methodFather;

                        $myClass->addMethod($cloneMethodFather);
                        $methodFather->setMyClass($myClass);
                    }

                    foreach ($myClassFather->getProperties() as $propertyFather) {
                        $myClass->addProperty(clone $propertyFather);
                    }
                }
            }
        }
    }

    #[\Override]
    public function enterBlock(Block $block, ?Block $prior = null): void
    {
        $this->insideInclude = false;
        if (!($this->context->getCurrentOp() instanceof Include_)) {
            $myBlock = new MyBlock($this->context->getCurrentLine(), $this->context->getCurrentColumn());
            $myBlock->setStartAddressBlock(count($this->context->requireCurrentMycode()->getCodes()));
            $this->context->setCurrentBlock($myBlock);

            array_push($this->blocksStack, $myBlock);

            $this->sBlocks[$block] = $myBlock;

            $instBlock = new MyInstruction(Opcodes::ENTER_BLOCK);
            $instBlock->addProperty(MyInstruction::MYBLOCK, $myBlock);
            $this->context->requireCurrentMycode()->addCode($instBlock);

            // block is for himself a parent block (handle dataflow for first block)
            $block->addParent($block);

            // params are part of the first block
            foreach ($this->context->requireCurrentFunc()->getParams() as $param) {
                $instDef = new MyInstruction(Opcodes::DEFINITION);
                $instDef->addProperty(MyInstruction::DEF, $param);
                $this->context->requireCurrentMycode()->addCode($instDef);
            }
            // end
        } else {
            $this->insideInclude = true;
        }
    }

    #[\Override]
    public function skipBlock(Block $block, ?Block $prior = null): void
    {
    }

    #[\Override]
    public function leaveOp(Op $op, Block $block): void
    {
    }

    #[\Override]
    public function leaveBlock(Block $block, ?Block $prior = null): void
    {
        if (!$this->insideInclude) {
            if ($this->sBlocks->offsetExists($block)) {
                $myBlock = $this->sBlocks[$block];

                $address_end_block = count($this->context->requireCurrentMycode()->getCodes());
                $myBlock->setEndAddressBlock($address_end_block);

                $instBlock = new MyInstruction(Opcodes::LEAVE_BLOCK);
                $instBlock->addProperty(MyInstruction::MYBLOCK, $myBlock);
                $this->context->requireCurrentMycode()->addCode($instBlock);

                array_pop($this->blocksStack);

                if (!empty($this->blocksStack)) {
                    $this->context->setCurrentBlock($this->blocksStack[count($this->blocksStack) - 1]);
                }
            }
        }
    }

    #[\Override]
    public function enterFunc(Func $func): void
    {
        $myFunction = new MyFunction($func->name);
        $this->context->setCurrentMycode($myFunction->getMyCode());

        $instFunc = new MyInstruction(Opcodes::ENTER_FUNCTION);
        $instFunc->addProperty(MyInstruction::MYFUNC, $myFunction);
        $this->context->requireCurrentMycode()->addCode($instFunc);

        $className = Common::literalValue($func->class);
        if (!is_null($className)) {
            // at this moment class is defined
            $myClass = $this->context->getClasses()->getMyClass($className);

            if (!is_null($myClass)) {
                $myClass->addMethod($myFunction);

                $myFunction->setVisibility(Common::getTypeVisibility($func->flags));
                $myFunction->addType(MyFunction::TYPE_FUNC_METHOD);
                $myFunction->setMyClass($myClass);

                if (($func->flags & Func::FLAG_STATIC) === Func::FLAG_STATIC) {
                    $myFunction->addType(MyFunction::TYPE_FUNC_STATIC);
                }

                $mythisdef = new MyDefinition(
                    0,
                    $this->context->getCurrentMyFile(),
                    0,
                    0,
                    "this"
                );

                $mythisdef->addType(MyDefinition::TYPE_INSTANCE);
                $mythisdef->requireCurrentState()->addType(MyDefinition::TYPE_INSTANCE);

                $myFunction->setThisDef($mythisdef);
            }
        }

        foreach ($func->params as $param) {
            $paramName = Common::literalValue($param->name);
            $byref = $param->byRef;

            $myDef = new MyDefinition(
                0,
                $this->context->getCurrentMyFile(),
                $param->getLine(),
                $param->getAttribute("startFilePos", -1),
                $paramName
            );

            if ($byref) {
                $myDef->addType(MyDefinition::TYPE_REFERENCE);
            }

            $myFunction->addParam($myDef);
        }

        $this->context->setCurrentFunc($myFunction);
    }

    #[\Override]
    public function leaveFunc(Func $func): void
    {
        $myCodeCodes = $this->context->requireCurrentMycode()->getCodes();

        $inst = $myCodeCodes[array_key_last($myCodeCodes)];

        // we can have a block opened and we need to leave it
        if ($inst->getOpcode() !== Opcodes::LEAVE_BLOCK) {
            if (
                !is_null($this->context->getCurrentBlock())
                && $this->sBlocks->offsetExists($this->context->getCurrentBlock())
            ) {
                $myBlock = $this->sBlocks[$this->context->getCurrentBlock()];
                $myBlock->setEndAddressBlock(count($this->context->requireCurrentMycode()->getCodes()));

                $instBlock = new MyInstruction(Opcodes::LEAVE_BLOCK);
                $instBlock->addProperty(MyInstruction::MYBLOCK, $myBlock);
                $this->context->requireCurrentMycode()->addCode($instBlock);
            }
        }

        $myFunction = $this->context->getCurrentFunc();

        $myFunction->setLastLine($this->context->getCurrentLine());
        $myFunction->setLastColumn($this->context->getCurrentColumn());

        $instFunc = new MyInstruction(Opcodes::LEAVE_FUNCTION);
        $instFunc->addProperty(MyInstruction::MYFUNC, $myFunction);
        $this->context->requireCurrentMycode()->addCode($instFunc);

        $this->context->addTmpFunctions($myFunction);
    }

    #[\Override]
    public function enterOp(Op $op, Block $block): void
    {
        $this->context->setCurrentOp($op);

        // for theses objects getline et getcolumn methods exists except for assertion
        if (
            $op instanceof Stmt ||
            ($op instanceof Op\Expr && !($op instanceof Assertion)) ||
            $op instanceof Terminal
        ) {
            if ($op->getLine() !== -1 && $op->getAttribute("startFilePos", -1) !== -1) {
                $this->context->setCurrentLine($op->getLine());
                $this->context->setCurrentColumn($op->getAttribute("startFilePos", -1));
            }
        }

        if (
            $op instanceof BinaryOp
            && !($op instanceof Concat)
        ) {
            $instBinary = new MyInstruction(Opcodes::BINARYOP);
            $instBinary->addProperty(MyInstruction::LEFTID, $this->context->requireCurrentFunc()->getOpId($op->left));
            $instBinary->addProperty(MyInstruction::RIGHTID, $this->context->requireCurrentFunc()->getOpId($op->right));
            $instBinary->addProperty(
                MyInstruction::RESULTID,
                $this->context->requireCurrentFunc()->getOpId($op->result)
            );
            $this->context->requireCurrentMycode()->addCode($instBinary);
        } elseif ($op instanceof BooleanNot) {
            $instNotBoolean = new MyInstruction(Opcodes::COND_BOOLEAN_NOT);
            $instNotBoolean->addProperty(
                MyInstruction::EXPRID,
                $this->context->requireCurrentFunc()->getOpId($op->expr)
            );
            $instNotBoolean->addProperty(
                MyInstruction::RESULTID,
                $this->context->requireCurrentFunc()->getOpId($op->result)
            );
            $this->context->requireCurrentMycode()->addCode($instNotBoolean);
        } elseif ($op instanceof JumpIf) {
            $instStartIf = new MyInstruction(Opcodes::COND_START_IF);
            $instStartIf->addProperty(MyInstruction::EXPRID, $this->context->requireCurrentFunc()->getOpId($op->cond));
            $this->context->requireCurrentMycode()->addCode($instStartIf);

            $this->blockIfToBeResolved[] = [$instStartIf, $block, $op->if, $op->else];
        } elseif ($op instanceof Value) {
            $instIterator = new MyInstruction(Opcodes::ITERATOR);
            Expr::implicitfetch($this->context, $op->var, null);
            $instIterator->addProperty(MyInstruction::VARID, $this->context->requireCurrentFunc()->getOpId($op->var));
            $instIterator->addProperty(
                MyInstruction::RESULTID,
                $this->context->requireCurrentFunc()->getOpId($op->result)
            );
            $this->context->requireCurrentMycode()->addCode($instIterator);
        } elseif ($op instanceof GlobalVar) {
            $myDefGlobal = new MyDefinition(
                $this->context->requireCurrentBlock()->getId(),
                $this->context->getCurrentMyFile(),
                $this->context->getCurrentLine(),
                $this->context->getCurrentColumn(),
                Common::literalValue($op->var)
            );
            $myDefGlobal->setType(MyDefinition::TYPE_GLOBAL);

            $instDef = new MyInstruction(Opcodes::DEFINITION);
            $instDef->addProperty(MyInstruction::DEF, $myDefGlobal);
            $this->context->requireCurrentMycode()->addCode($instDef);

            $this->context->requireCurrentFunc()->setHasGlobalVariables(true);
        } elseif ($op instanceof Return_) {
            // we put the ids of return as last block id
            $this->context->requireCurrentFunc()->addLastBlockId($this->context->requireCurrentBlock()->getId());

            if (isset($op->expr)) {
                if (isset($op->expr->original)) {
                    Expr::implicitfetch($this->context, $op->expr, "right");
                }

                Assign::instruction($this->context, $op, $op->expr, null, true, false);

                $inst = new MyInstruction(Opcodes::RETURN_FUNCTION);
                $inst->addProperty(MyInstruction::RETURN_DEFS, $this->context->requireCurrentFunc()->getReturnDefs());
                $this->context->requireCurrentMycode()->addCode($inst);
            }
        } elseif ($op instanceof Op\Expr\Assign || $op instanceof AssignRef) {
            if (isset($op->expr) && isset($op->var)) {
                Assign::instruction($this->context, $op, $op->expr, $op->var);
            }
        } elseif ($op instanceof Class_) {
            $className = Common::getNameDefinition($op);

            $myClass = new MyClass(
                $this->context->getCurrentLine(),
                $this->context->getCurrentColumn(),
                $className
            );

            if (!is_null($op->extends)) {
                $myClass->setExtendsOf(Common::literalValue($op->extends));
            }

            $this->context->getClasses()->addMyclass($myClass);

            foreach ($op->stmts->children as $property) {
                if ($property instanceof Property) {
                    $propertyName = Common::getNameDefinition($property);
                    $visibility = Common::getTypeVisibility($property->visibility);

                    $myProperty = new MyProperty(
                        $this->context->requireCurrentBlock()->getId(),
                        $this->context->getCurrentMyFile(),
                        $property->getLine(),
                        $property->getAttribute("startFilePos", -1),
                        $propertyName
                    );
                    $myProperty->setVisibility($visibility);
                    $myClass->addProperty($myProperty);

                    if ($property->static) {
                        $myProperty->addType(MyDefinition::TYPE_STATIC_PROPERTY);
                        $myProperty->requireCurrentState()->addType(MyDefinition::TYPE_STATIC_PROPERTY);
                    }
                }
            }

            $instClass = new MyInstruction(Opcodes::CLASSE);
            $instClass->addProperty(MyInstruction::MYCLASS, $myClass);
            $this->context->requireCurrentMycode()->addCode($instClass);
        } else {
            Expr::explicitfetch($this->context, $op, null);
        }
    }
}
