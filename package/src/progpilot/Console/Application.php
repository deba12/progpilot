<?php

/*
 * This file is part of ProgPilot, a static analyzer for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */

namespace progpilot\Console;

use Symfony\Component\Console\Application as BaseApplication;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputDefinition;
use Symfony\Component\Console\Output\OutputInterface;

class Application extends BaseApplication
{
    public const NAME = 'progpilot';
    public const VERSION = '1.3.0';

    public function __construct()
    {
        parent::__construct(self::NAME, self::VERSION);
    }

    #[\Override]
    public function run(?InputInterface $input = null, ?OutputInterface $output = null): int
    {
        $this->setCatchExceptions(true);
        return parent::run($input, $output);
    }

    #[\Override]
    public function getDefinition(): InputDefinition
    {
        $inputDefinition = parent::getDefinition();
        // clear out the normal first argument, which is the command name
        $inputDefinition->setArguments();

        return $inputDefinition;
    }

    #[\Override]
    protected function getCommandName(InputInterface $input): ?string
    {
        return 'progpilot';
    }
}
