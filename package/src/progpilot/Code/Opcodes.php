<?php

/*
 * This file is part of ProgPilot, a static analyzer for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


namespace progpilot\Code;

class Opcodes
{
    public const LEAVE_BLOCK = 1;
    public const ENTER_BLOCK = 2;
    public const ENTER_FUNCTION = 3;
    public const LEAVE_FUNCTION = 4;
    public const DEFINITION = 5;
    public const START_ASSIGN = 6;
    public const END_ASSIGN = 7;
    public const CONCAT_LEFT = 11;
    public const CONCAT_RIGHT = 12;
    public const CONCAT_LIST = 13;
    public const FUNC_CALL = 14;
    public const RETURN_FUNCTION = 15;
    public const CLASSE = 16;
    public const ASSERTION = 17;
    public const COND_START_IF = 18;
    public const COND_BOOLEAN_NOT = 19;
    public const NEW_INCLUDE = 20;
    public const PROPERTY_FETCH = 21;
    public const ARRAYDIM_FETCH = 22;
    public const VARIABLE = 23;
    public const ASSIGN = 24;
    public const ARGUMENT = 25;
    public const VARIABLE_FETCH = 26;
    public const LITERAL_FETCH = 27;
    public const STATIC_PROPERTY_FETCH = 28;
    public const CAST = 29;
    public const CONST_FETCH = 30;
    public const ITERATOR = 31;
    public const ARRAY_EXPR = 32;
    public const BINARYOP = 33;
}
