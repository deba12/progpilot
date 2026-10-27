<?php

/*
 * This file is part of ProgPilot, a static analyzer for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


declare(strict_types=1);

namespace progpilot\Transformations\Php\Exprs;

use progpilot\Context;
use PHPCfg\Op\Expr\BinaryOp\Concat;
use PHPCfg\Op\Expr\ConcatList;
use PHPCfg\Op;
use progpilot\Transformations\Php\Expr;
use progpilot\Code\MyInstruction;
use progpilot\Code\Opcodes;

class ConcatFetch
{
    public static function concatFetch(Context $context, Op $op, ?string $expr): void
    {
        if ($op instanceof Concat) {
            $instDefChained = new MyInstruction(Opcodes::CONCAT_LEFT);
            Expr::implicitfetch($context, $op->left, $expr);
            $instDefChained->addProperty(MyInstruction::LEFTID, $context->requireCurrentFunc()->getOpId($op->left));
            Expr::implicitfetch($context, $op->right, $expr);
            $opIds = [];
            $opIds[] = $context->requireCurrentFunc()->getOpId($op->right);
            $instDefChained->addProperty(MyInstruction::RIGHTID, $opIds);
            $instDefChained->addProperty(MyInstruction::RESULTID, $context->requireCurrentFunc()->getOpId($op->result));

            $context->requireCurrentMycode()->addCode($instDefChained);
        } elseif ($op instanceof ConcatList) {
            $instDefChained = new MyInstruction(Opcodes::CONCAT_LEFT);

            $opIds = [];
            foreach ($op->list as $opsbis) {
                $opIds[] = $context->requireCurrentFunc()->getOpId($opsbis);
                Expr::implicitfetch($context, $opsbis, $expr);
            }
            $instDefChained->addProperty(MyInstruction::RIGHTID, $opIds);
            $instDefChained->addProperty(MyInstruction::RESULTID, $context->requireCurrentFunc()->getOpId($op->result));
            $context->requireCurrentMycode()->addCode($instDefChained);
        }
    }
}
