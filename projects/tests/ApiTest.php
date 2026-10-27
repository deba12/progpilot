<?php

require_once './vendor/autoload.php';

use PHPUnit\Framework\TestCase;
use progpilot\Command\ProgpilotCommand;
use Symfony\Component\Console\Tester\CommandTester;
use progpilot\Analyzer;
use progpilot\Code\MyInstruction;
use progpilot\Analysis\CustomAnalysis;
use progpilot\Context;
use progpilot\Inputs\MyCustomRule;
use progpilot\Inputs\MyInputsInternalApi;
use progpilot\Objects\MyBlock;
use progpilot\Objects\MyDefState;
use progpilot\Objects\MyFunction;

/**
 * Behaviours of the public API that the vulnerability fixtures do not exercise:
 * what the configuration accepts, and what the getters return when nothing is current.
 */
final class ApiTest extends TestCase
{
    public function testExclusionsAcceptNullAndArraysAndIgnoreNonStrings(): void
    {
        $context = new Context();

        $context->inputs->setExclusions(null);
        $this->assertSame([], $context->inputs->getExclusions());

        $context->inputs->setExclusions(['vendor', 5, 'tests', 'vendor']);
        $this->assertSame(['vendor', 'tests'], $context->inputs->getExclusions());

        $context->inputs->setInclusions(['src', false]);
        $this->assertSame(['src'], $context->inputs->getInclusions());
    }

    public function testFalsePositivesAcceptAnArrayOfVulnerabilities(): void
    {
        $context = new Context();

        $context->inputs->setFalsePositives(null);
        $this->assertCount(0, $context->inputs->getFalsePositives());

        $context->inputs->setFalsePositives([['vuln_id' => 'abc'], ['vuln_id' => 'def']]);
        $this->assertCount(2, $context->inputs->getFalsePositives());
    }

    public function testFalsePositivesWithoutVulnIdAreRejected(): void
    {
        $this->expectException(Exception::class);
        (new Context())->inputs->setFalsePositives([['id' => 'abc']]);
    }

    public function testFalsePositivesFileMustExist(): void
    {
        $this->expectException(Exception::class);
        (new Context())->inputs->setFalsePositives('/does/not/exist.json');
    }

    public function testResolvePathMakesRelativePathsAbsolute(): void
    {
        $this->assertSame(realpath('./composer.json'), MyInputsInternalApi::resolvePath('./composer.json'));
        $this->assertSame(realpath('./vendor/autoload.php'), MyInputsInternalApi::resolvePath('vendor/autoload.php'));
        // a bare name may be a file or folder name used as a filter, it is kept as is
        $this->assertSame('composer.json', MyInputsInternalApi::resolvePath('composer.json'));
    }

    public function testNothingIsCurrentOnAFreshContext(): void
    {
        $context = new Context();

        $this->assertNull($context->getCurrentFunc());
        $this->assertNull($context->getCurrentBlock());
        $this->assertNull($context->getCurrentMycode());
        $this->assertNull($context->getCurrentMyfile());
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('requireProvider')]
    public function testRequireVariantsThrowWhenNothingIsCurrent(string $method): void
    {
        $this->expectException(LogicException::class);
        (new Context())->$method();
    }

    /**
     * @return array<string, array{string}>
     */
    public static function requireProvider(): array
    {
        return [
            'function' => ['requireCurrentFunc'],
            'block' => ['requireCurrentBlock'],
            'code' => ['requireCurrentMycode'],
            'file' => ['requireCurrentMyfile'],
        ];
    }

    public function testRequireVariantsReturnWhatIsCurrent(): void
    {
        $context = new Context();
        $func = new MyFunction('f');
        $block = new MyBlock(1, 1);

        $context->setCurrentFunc($func);
        $context->setCurrentBlock($block);

        $this->assertSame($func, $context->requireCurrentFunc());
        $this->assertSame($block, $context->requireCurrentBlock());
    }

    public function testLastKnownValuesKeepNullAndNormaliseScalars(): void
    {
        $state = new MyDefState();

        $state->addLastKnownValue(null);
        $state->addLastKnownValue(' 5 ');
        $state->addLastKnownValue(7);

        $this->assertSame([null, '5', '7'], $state->getLastKnownValues());
    }

    public function testOperandIdsAreNullForNothing(): void
    {
        $this->assertNull((new MyFunction('f'))->getOpId(null));
    }

    public function testUnknownBlockIsNull(): void
    {
        $this->assertNull((new MyFunction('f'))->getBlockById(12345));
    }

    public function testInstructionPropertiesDefaultToNull(): void
    {
        $instruction = new MyInstruction(1);

        $this->assertNull($instruction->getProperty(MyInstruction::DEF));
        $this->assertFalse($instruction->isPropertyExist('argdef0'));

        $instruction->addProperty(MyInstruction::FUNCNAME, 'strlen');
        $this->assertSame('strlen', $instruction->getProperty(MyInstruction::FUNCNAME));
    }

    public function testDefineObjectIsSkippedForNonDefinitionsWithoutAReturnDefinition(): void
    {
        $rule = new MyCustomRule('define an object');
        $rule->setExtra('SomeClass');

        $result = CustomAnalysis::returnObjectCreateObject(new Context(), $rule, new MyFunction('f'), null);

        $this->assertNull($result);
    }

    public function testAnalysingASourceStringWithoutPhpTagFindsNothing(): void
    {
        $context = new Context();
        $context->inputs->setCode('plain text');
        $context->inputs->setFile('./composer.json');

        (new Analyzer())->run($context);

        $this->assertSame([], $context->outputs->getResults());
    }

    /**
     * @param list<string> $files
     * @return array{int, string}
     */
    private function runCommand(array $files, ?string $configuration = null): array
    {
        $tester = new CommandTester(new ProgpilotCommand());
        $input = ['files' => $files];
        if ($configuration !== null) {
            $input['--configuration'] = $configuration;
        }

        ob_start();
        $status = $tester->execute($input);

        return [$status, (string) ob_get_clean()];
    }

    public function testCommandIgnoresPathsThatDoNotExist(): void
    {
        [$status, $output] = $this->runCommand(['/does/not/exist.php', '/does/not/exist/either']);

        $this->assertSame(0, $status);
        $this->assertSame([], json_decode($output, true));
    }

    public function testCommandReportsAVulnerabilityWithExitStatusOne(): void
    {
        [$status, $output] = $this->runCommand(['./tests/generic/alias1.php']);

        $this->assertSame(1, $status);
        $results = json_decode($output, true);
        $this->assertNotEmpty($results);
        $this->assertArrayHasKey('vuln_name', $results[0]);
    }

    public function testCommandMixesExistingAndMissingPaths(): void
    {
        [$status] = $this->runCommand(['/does/not/exist.php', './tests/generic/alias1.php']);

        $this->assertSame(1, $status);
    }

    public function testCommandRejectsAMissingConfigurationFileWithoutCrashing(): void
    {
        [$status, $output] = $this->runCommand(['./tests/generic/alias1.php'], '/does/not/exist.yml');

        $this->assertSame(0, $status);
        $this->assertStringContainsString('exist', $output);
    }

    public function testAnalyzerIgnoresAMissingFileAndFolder(): void
    {
        $context = new Context();
        $context->inputs->setFile('/does/not/exist.php');
        (new Analyzer())->run($context);
        $this->assertSame([], $context->outputs->getResults());

        $context = new Context();
        $context->inputs->setFolder('/does/not/exist');
        (new Analyzer())->run($context);
        $this->assertSame([], $context->outputs->getResults());
    }

    public function testConfigurationOptionsAcceptQuotedNumbers(): void
    {
        $file = tempnam(sys_get_temp_dir(), 'progpilot');
        file_put_contents($file, "options:\n    max_file_analysis_duration: \"10\"\n    max_definitions: \"100\"\n"
            . "    max_file_size: \"500000\"\n    debug_mode: 1\n    pretty_print: 0\n");

        try {
            $context = new Context();
            $context->setConfiguration($file);
            (new Analyzer())->run($context);

            $this->assertSame(10, $context->getMaxFileAnalysisDuration());
            $this->assertSame(100, $context->getMaxDefinitions());
            $this->assertSame(500000, $context->getMaxFileSize());
            $this->assertTrue($context->isDebugMode());
            $this->assertFalse($context->getPrettyPrint());
        } finally {
            unlink($file);
        }
    }
}
