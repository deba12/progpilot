<?php

/*
 * This file is part of ProgPilot, a static analyzer for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


namespace progpilot\Transformations\Php;

use PHPCfg\Operand\Literal;
use PHPCfg\Op\Expr\PropertyFetch;
use PHPCfg\Op\Expr\StaticPropertyFetch;
use PHPCfg\Op\Expr\ArrayDimFetch;
use PHPCfg\Op\Expr\Array_;
use PHPCfg\Op\Expr\FuncCall;
use PHPCfg\Operand\BoundVariable;
use PHPCfg\Op\Expr\ConstFetch;
use PHPCfg\Op\Iterator\Value;
use PHPCfg\Op;
use PHPCfg\Operand;
use progpilot\Objects\MyOp;

class Common
{
    /**
     * Returns the value of a literal operand, null for any other kind of operand.
     */
    public static function literalValue(?Operand $operand): mixed
    {
        return $operand instanceof Literal ? $operand->value : null;
    }

    public static function validLastKnownValue(string $value): bool
    {
        if (strpos($value, '\n') === false && strpos($value, '\r') === false && strlen($value) < 200) {
            return true;
        }

        return false;
    }

    public static function isChainedKnownType(Op $op): bool
    {
        if (
            $op instanceof PropertyFetch
            || $op instanceof StaticPropertyFetch
            || $op instanceof ArrayDimFetch
        ) {
            return true;
        }

        return false;
    }

    public static function getTypeDef(Op $op): ?string
    {
        // the order is important (current it breaks array14.php)
        // first we look for the left side
        // this->foo

        if (isset($op->var->ops[0])) {
            if (
                isset($op->var->ops[0]->var->ops[0])
                && Common::isChainedKnownType($op->var->ops[0]->var->ops[0])
                && $op->var->ops[0]->var->ops[0] !== $op->var->ops[0]
            ) {
                return Common::getTypeDef($op->var->ops[0]);
            } else {
                if ($op->var->ops[0] instanceof PropertyFetch) {
                    return MyOp::TYPE_PROPERTY;
                }

                if ($op->var->ops[0] instanceof StaticPropertyFetch) {
                    return MyOp::TYPE_STATIC_PROPERTY;
                }

                if ($op->var->ops[0] instanceof ArrayDimFetch) {
                    return MyOp::TYPE_ARRAY;
                }

                if ($op->var->ops[0] instanceof Array_) {
                    return MyOp::TYPE_ARRAY_EXPR;
                }

                if (isset($op->var->original->name->value)) {
                    return MyOp::TYPE_VARIABLE;
                }
            }
        }

        // then for the right
        // foo = array()
        // foo = define("FOO")
        if (isset($op->name)) {
            if (
                $op instanceof FuncCall
                && $op->name instanceof Literal
                && $op->name->value === "define"
            ) {
                return MyOp::TYPE_CONST;
            }
        }

        if (isset($op->expr->ops[0])) {
            if ($op->expr->ops[0] instanceof Array_) {
                return MyOp::TYPE_ARRAY_EXPR;
            }
        }

        return null;
    }

    public static function getNameDefinition($ops, bool $lookingForProperty = false): string
    {
        //  $this->property = property
        if (
            $lookingForProperty
            && ($ops instanceof PropertyFetch || $ops instanceof StaticPropertyFetch)
            && isset($ops->name->value)
        ) {
            return $ops->name->value;
        }

        //  $this->property = this
        if (isset($ops->var) && $ops->var instanceof BoundVariable && isset($ops->var->name->value)) {
            return $ops->var->name->value;
        }

        if (isset($ops->ops[0])) {
            if ($ops->ops[0] instanceof ConstFetch) {
                return Common::getNameDefinition($ops->ops[0], $lookingForProperty);
            }

            if ($ops->ops[0] instanceof ArrayDimFetch) {
                return Common::getNameDefinition($ops->ops[0], $lookingForProperty);
            }

            if ($ops->ops[0] instanceof PropertyFetch) {
                return Common::getNameDefinition($ops->ops[0], $lookingForProperty);
            }

            if ($ops->ops[0] instanceof StaticPropertyFetch) {
                return Common::getNameDefinition($ops->ops[0], $lookingForProperty);
            }
        }

        if (isset($ops->var->ops)) {
            foreach ($ops->var->ops as $op) {
                if ($op instanceof ConstFetch) {
                    return Common::getNameDefinition($op, $lookingForProperty);
                }

                if ($op instanceof ArrayDimFetch) {
                    return Common::getNameDefinition($op, $lookingForProperty);
                }

                if ($op instanceof PropertyFetch) {
                    return Common::getNameDefinition($op, $lookingForProperty);
                }

                if ($op instanceof StaticPropertyFetch) {
                    return Common::getNameDefinition($op, $lookingForProperty);
                }
            }
        }

        if ($ops instanceof Value) {
            return Common::getNameDefinition($ops->var, $lookingForProperty);
        }

        // use variable
        if (isset($ops->original->name->value)) {
            return $ops->original->name->value;
        }

        // def variable
        if (isset($ops->var->original->name->value)) {
            return $ops->var->original->name->value;
        }

        // static property
        if (isset($ops->class->value)) {
            return $ops->class->value;
        }

        // class name
        if (isset($ops->name->value)) {
            return $ops->name->value;
        }

        // arrayexpr
        if (isset($ops->value)) {
            return $ops->value;
        }

        return "";
    }

    /*
         public const FLAG_PUBLIC      = 0x01;
         public const FLAG_PROTECTED   = 0x02;
         public const FLAG_PRIVATE     = 0x04;
         public const FLAG_STATIC      = 0x08;
         public const FLAG_ABSTRACT    = 0x10;
         public const FLAG_FINAL       = 0x20;
         public const FLAG_RETURNS_REF = 0x40;
         public const FLAG_CLOSURE     = 0x80;
     */

    public static function getTypeVisibility(int $visibility): string
    {
        switch ($visibility) {
            case 1:
                return "public";
            case 2:
                return "protected";
            case 4:
                return "private";
            default:
                return "public";
        }
    }
}
