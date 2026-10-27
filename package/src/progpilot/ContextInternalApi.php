<?php

/*
 * This file is part of ProgPilot, a static analyzer for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


namespace progpilot;

use progpilot\Dataflow\Definitions;
use stdClass;
use progpilot\Inputs\MyInputs;
use progpilot\Outputs\MyOutputs;
use progpilot\Dataflow\Objects;
use progpilot\Dataflow\Classes;
use progpilot\Dataflow\Functions;
use progpilot\Code\MyCode;
use PHPCfg\Op;
use progpilot\Objects\MyBlock;
use progpilot\Objects\MyFile;
use Symfony\Component\Yaml\Exception\ParseException;
use Symfony\Component\Yaml\Parser;
use progpilot\Utils;
use progpilot\Objects\MyFunction;

abstract class ContextInternalApi
{
    abstract public function setAnalyzeIncludes($analyzeIncludes);

    abstract public function setMaxFileAnalysisDuration($maxFileAnalysisDuration);

    abstract public function setMaxDefinitions($maxDefinitions);

    abstract public function setMaxFileSize($maxFileSize);

    abstract public function setMaxMemory($maxMemory);

    abstract public function setDebugMode($bool);

    abstract public function setPrettyPrint($bool);

    protected array $arrayIncludes;
    protected array $arrayRequires;

    protected ?MyCode $currentMyCode = null;
    protected ?Op $currentOp = null;
    protected MyBlock|int|null $currentBlock = null;
    protected ?int $currentLine = null;
    protected ?int $currentColumn = null;
    protected ?MyFunction $currentFunc = null;
    protected ?MyFile $currentMyFile = null;
    protected Classes $classes;
    protected Objects $objects;
    protected Functions $functions;
    protected ?string $path = null;
    protected bool $analyzeIncludes;
    protected ?string $configurationFile = null;
    protected bool $debugMode;
    protected bool $prettyPrint;
    protected int $maxFileAnalysisDuration;
    protected int $maxDefinitions;
    protected int $maxFileSize;
    protected int $maxMemory;
    protected array $defsMain;
    protected array $tmpfunctions;
    /**
     * @var list<array<mixed>>
     */
    protected array $callStack;
    protected $calltonamespaces;
    protected $namespaces;

    protected array $analyzedDataFiles;

    /**
     * @var MyInputs
     */
    public MyInputs $inputs;
    /**
     * @var MyOutputs
     */
    public MyOutputs $outputs;

    public function __construct()
    {
        $this->configurationFile = null;
        $this->analyzeIncludes = true;
        $this->debugMode = false;
        $this->prettyPrint = true;
        $this->maxFileAnalysisDuration = 30;
        $this->maxDefinitions = 500;
        $this->maxFileSize = 1000000;
        $this->maxMemory = 4000000000; // 4GB

        $this->inputs = new MyInputs();
        $this->outputs = new MyOutputs();

        $this->objects = new Objects();
        $this->classes = new Classes();
        $this->functions = new Functions();

        $this->resetInternalValues();

        $this->currentFunc = null;
        $this->currentMyFile = null;
        $this->arrayIncludes = [];
        $this->arrayRequires = [];
        $this->analyzedDataFiles = [];

        $this->defsMain = [];
        $this->tmpfunctions = [];
        $this->callStack = [];
    }

    /**
     * @param list<MyFunction|array<mixed>|Definitions|stdClass> $val
     */
    public function pushToCallStack(array $val)
    {
        array_push($this->callStack, $val);
    }

    /**
     * @return list<MyFunction|array<mixed>|Definitions|stdClass>
     */
    public function popFromCallStack(): array
    {
        return array_pop($this->callStack);
    }

    /**
     * @param list<array<mixed>> $callStack
     */
    public function setCallStack(array $callStack)
    {
        $this->callStack = $callStack;
    }

    /**
     * @return list<array<mixed>>
     */
    public function getCallStack(): array
    {
        return $this->callStack;
    }

    public function inCallStack(MyFunction $curFunc): bool
    {
        foreach ($this->callStack as $call) {
            $callFunc = $call[0];

            if (
                $callFunc->getName() === $curFunc->getName()
                && !$callFunc->isType(MyFunction::TYPE_FUNC_METHOD)
                && !$curFunc->isType(MyFunction::TYPE_FUNC_METHOD)
            ) {
                return true;
            }

            if (
                $callFunc->getName() === $curFunc->getName()
                && $callFunc->isType(MyFunction::TYPE_FUNC_METHOD)
                && $curFunc->isType(MyFunction::TYPE_FUNC_METHOD)
            ) {
                $curClass = $curFunc->getMyClass();
                $callClass = $callFunc->getMyClass();

                if ($curClass->getName() === $callClass->getName()) {
                    return true;
                }

                $curClassExtends = $curClass->getExtendsOf();
                $callClassExtends = $callClass->getExtendsOf();

                if (
                    isset($curClassExtends) && isset($callClassExtends)
                    && $curClassExtends === $callClassExtends
                ) {
                    return true;
                }
            }
        }

        return false;
    }

    public function addTmpFunctions(MyFunction $myfunc)
    {
        $this->tmpfunctions[] = $myfunc;
    }

    public function clearTmpFunctions()
    {
        $this->tmpfunctions = [];
    }

    /**
     * @return list<MyFunction>
     */
    public function getTmpFunctions(): array
    {
        return $this->tmpfunctions;
    }

    public function addDataAnalyzedFile(string $file)
    {
        if (!in_array($file, $this->analyzedDataFiles)) {
            $this->analyzedDataFiles[] = $file;
        }
    }

    public function isFileDataAnalyzed(string $file): bool
    {
        return in_array($file, $this->analyzedDataFiles);
    }

    public function getDefsMain()
    {
        return $this->defsMain;
    }

    public function setDefsMain(array $defsMain)
    {
        $this->defsMain = $defsMain;
    }

    public function addFileandNamepace(string $file, string $namespace)
    {
        $this->namespaces["$namespace"] = $file;
    }

    public function getFileFromNamespace(string $namespace): ?string
    {
        if (isset($this->namespaces["$namespace"])) {
            return $this->namespaces["$namespace"];
        }

        return null;
    }

    public function addCallToNamespace(string $namespace)
    {
        if (!isset($this->calltonamespaces["" . $this->currentMyFile->getName() . ""])) {
            $this->calltonamespaces["" . $this->currentMyFile->getName() . ""] = [];
        }

        if (!in_array($namespace, $this->calltonamespaces["" . $this->currentMyFile->getName() . ""], true)) {
            $this->calltonamespaces["" . $this->currentMyFile->getName() . ""][] = $namespace;
        }
    }

    /**
     * @return list<string>|null
     */
    public function getCallsToNamespace(string $file): ?array
    {
        if (isset($this->calltonamespaces["$file"])) {
            return $this->calltonamespaces["$file"];
        }

        return null;
    }

    public function resetInternalLowvalues()
    {
        $this->currentOp = null;
        $this->currentBlock = null;
        $this->currentLine = -1;
        $this->currentColumn = -1;
        $this->currentFunc = null;
        $this->currentMyCode = null;
    }

    public function resetInternalValues()
    {
        $this->resetInternalLowvalues();

        $this->inputs->setCode(null);
    }

    public function resetCallStack()
    {
        $this->callStack = [];
    }

    public function resetIncludedFiles()
    {
        $this->arrayIncludes = [];
        $this->arrayRequires = [];
    }

    public function resetDataflow()
    {
        $this->analyzedDataFiles = [];
        $this->objects = new Objects();
        $this->classes = new Classes();
        $this->functions = new Functions();
    }

    public function setArrayIncludes(array $arrayIncludes)
    {
        $this->arrayIncludes = $arrayIncludes;
    }

    public function setArrayRequires(array $arrayRequires)
    {
        $this->arrayRequires = $arrayRequires;
    }

    public function &getArrayIncludes(): array
    {
        return $this->arrayIncludes;
    }

    public function &getArrayRequires(): array
    {
        return $this->arrayRequires;
    }

    public function getCurrentMycode(): ?MyCode
    {
        return $this->currentMyCode;
    }

    public function requireCurrentMycode(): MyCode
    {
        return $this->currentMyCode ?? throw new \LogicException('no code is being analyzed');
    }

    public function getCurrentOp(): ?Op
    {
        return $this->currentOp;
    }

    public function getCurrentBlock(): MyBlock|int|null
    {
        return $this->currentBlock;
    }

    public function requireCurrentBlock(): MyBlock|int
    {
        return $this->currentBlock ?? throw new \LogicException('no block is being analyzed');
    }

    public function getCurrentLine(): int
    {
        return $this->currentLine;
    }

    public function getCurrentColumn(): int
    {
        return $this->currentColumn;
    }

    public function getCurrentFunc(): ?MyFunction
    {
        return $this->currentFunc;
    }

    public function requireCurrentFunc(): MyFunction
    {
        return $this->currentFunc ?? throw new \LogicException('no function is being analyzed');
    }

    public function getObjects(): Objects
    {
        return $this->objects;
    }

    public function getClasses(): Classes
    {
        return $this->classes;
    }

    public function getFunctions(): Functions
    {
        return $this->functions;
    }

    public function getNbsOpInformationsAll()
    {
        $nb = 0;
        foreach ($this->getFunctions()->getFunctions() as $functionclasses) {
            foreach ($functionclasses as $functionnames) {
                foreach ($functionnames as $function) {
                    foreach ($function->getOpInformations() as $opInformation) {
                        if (isset($opInformation["chained_results"])) {
                            $nb += count($opInformation["chained_results"]);
                        }
                    }
                }
            }
        }

        return $nb;
    }

    public function getInputs()
    {
        return $this->inputs;
    }

    public function getOutputs()
    {
        return $this->outputs;
    }

    public function getPath(): string
    {
        return $this->path;
    }

    public function getCurrentMyfile(): ?MyFile
    {
        return $this->currentMyFile;
    }

    public function requireCurrentMyfile(): MyFile
    {
        return $this->currentMyFile ?? throw new \LogicException('no file is being analyzed');
    }

    public function setCurrentMyfile(MyFile $myFile)
    {
        $this->currentMyFile = $myFile;
    }

    public function setPath(string $path)
    {
        $this->path = $path;
    }

    public function setCurrentMycode(?MyCode $myCode)
    {
        $this->currentMyCode = $myCode;
    }

    public function setCurrentOp(?Op $currentOp)
    {
        $this->currentOp = $currentOp;
    }

    public function setCurrentBlock(MyBlock|int $currentBlock)
    {
        $this->currentBlock = $currentBlock;
    }

    public function setCurrentLine(int $currentLine)
    {
        $this->currentLine = $currentLine;
    }

    public function setCurrentColumn(int $currentColumn)
    {
        $this->currentColumn = $currentColumn;
    }

    public function setCurrentFunc(MyFunction $currentFunc)
    {
        $this->currentFunc = $currentFunc;
    }

    public function setObjects(Objects $objects)
    {
        $this->objects = $objects;
    }

    public function setClasses(Classes $classes)
    {
        $this->classes = $classes;
    }

    public function setFunctions(Functions $functions)
    {
        $this->functions = $functions;
    }

    public function setInputs(MyInputs $inputs)
    {
        $this->inputs = $inputs;
    }

    public function setOutputs(MyOutputs $outputs)
    {
        $this->outputs = $outputs;
    }

    public function readConfiguration()
    {
        if (!is_null($this->configurationFile)) {
            try {
                if (file_exists($this->configurationFile)) {
                    $yaml = new Parser();
                    $value = $yaml->parse(file_get_contents($this->configurationFile));

                    if (is_array($value)) {
                        if (isset($value["inputs"])) {
                            if (isset($value["inputs"]["customrules"])) {
                                $keep_defaults = true;
                                if (isset($value["inputs"]["customrules"]["keep_defaults"])) {
                                    $keep_defaults = $value["inputs"]["customrules"]["keep_defaults"];
                                }

                                if ($keep_defaults) {
                                    $this->inputs->addCustomRules($value["inputs"]["customrules"]["config_files"]);
                                } else {
                                    $this->inputs->setCustomRules($value["inputs"]["customrules"]["config_files"]);
                                }
                            }

                            if (isset($value["inputs"]["sources"])) {
                                $keep_defaults = true;
                                if (isset($value["inputs"]["sources"]["keep_defaults"])) {
                                    $keep_defaults = $value["inputs"]["sources"]["keep_defaults"];
                                }

                                if ($keep_defaults) {
                                    $this->inputs->addSources($value["inputs"]["sources"]["config_files"]);
                                } else {
                                    $this->inputs->setSources($value["inputs"]["sources"]["config_files"]);
                                }
                            }

                            if (isset($value["inputs"]["sinks"])) {
                                $keep_defaults = true;
                                if (isset($value["inputs"]["sinks"]["keep_defaults"])) {
                                    $keep_defaults = $value["inputs"]["sinks"]["keep_defaults"];
                                }

                                if ($keep_defaults) {
                                    $this->inputs->addSinks($value["inputs"]["sinks"]["config_files"]);
                                } else {
                                    $this->inputs->setSinks($value["inputs"]["sinks"]["config_files"]);
                                }
                            }

                            if (isset($value["inputs"]["validators"])) {
                                $keep_defaults = true;
                                if (isset($value["inputs"]["validators"]["keep_defaults"])) {
                                    $keep_defaults = $value["inputs"]["validators"]["keep_defaults"];
                                }

                                if ($keep_defaults) {
                                    $this->inputs->addValidators($value["inputs"]["validators"]["config_files"]);
                                } else {
                                    $this->inputs->setValidators($value["inputs"]["validators"]["config_files"]);
                                }
                            }

                            if (isset($value["inputs"]["sanitizers"])) {
                                $keep_defaults = true;
                                if (isset($value["inputs"]["sanitizers"]["keep_defaults"])) {
                                    $keep_defaults = $value["inputs"]["sanitizers"]["keep_defaults"];
                                }

                                if ($keep_defaults) {
                                    $this->inputs->addSanitizers($value["inputs"]["sanitizers"]["config_files"]);
                                } else {
                                    $this->inputs->setSanitizers($value["inputs"]["sanitizers"]["config_files"]);
                                }
                            }

                            if (isset($value["inputs"]["inclusions"])) {
                                $this->inputs->setInclusions($value["inputs"]["inclusions"]);
                            }

                            if (isset($value["inputs"]["exclusions"])) {
                                $this->inputs->setExclusions($value["inputs"]["exclusions"]);
                            }

                            if (isset($value["inputs"]["resolved_includes_file"])) {
                                $this->inputs->setResolvedIncludes($value["inputs"]["resolved_includes_file"]);
                            }

                            if (isset($value["inputs"]["false_positives"])) {
                                $this->inputs->setFalsePositives($value["inputs"]["false_positives"]);
                            }

                            if (isset($value["inputs"]["dev_mode"])) {
                                $this->inputs->setDev($value["inputs"]["dev_mode"]);
                            }
                        }

                        if (isset($value["outputs"])) {
                            if (isset($value["outputs"]["tainted_flow"])) {
                                $this->outputs->taintedFlow($value["outputs"]["tainted_flow"]);
                            }

                            if (isset($value["outputs"]["sarif_output"])) {
                                $this->outputs->sarifOutput($value["outputs"]["sarif_output"]);
                            }

                            if (isset($value["outputs"]["include_failures_file"])) {
                                $this->outputs->setIncludeFailuresFile($value["outputs"]["include_failures_file"]);
                            }
                        }

                        if (isset($value["options"])) {
                            if (isset($value["options"]["analyze_includes"])) {
                                $this->setAnalyzeIncludes($value["options"]["analyze_includes"]);
                            }

                            if (isset($value["options"]["max_file_analysis_duration"])) {
                                $this->setMaxFileAnalysisDuration($value["options"]["max_file_analysis_duration"]);
                            }

                            if (isset($value["options"]["max_definitions"])) {
                                $this->setMaxDefinitions($value["options"]["max_definitions"]);
                            }

                            if (isset($value["options"]["max_file_size"])) {
                                $this->setMaxFileSize($value["options"]["max_file_size"]);
                            }

                            if (isset($value["options"]["max_memory"])) {
                                $this->setMaxMemory($value["options"]["max_memory"]);
                            }

                            if (isset($value["options"]["debug_mode"])) {
                                $this->setDebugMode($value["options"]["debug_mode"]);
                            }

                            if (isset($value["options"]["pretty_print"])) {
                                $this->setPrettyPrint($value["options"]["pretty_print"]);
                            }
                        }
                    }
                } else {
                    Utils::printError(
                        Lang::FILE_DOESNT_EXIST . " (" . Utils::encodeCharacters($this->configurationFile) . ")"
                    );
                }
            } catch (ParseException $e) {
                Utils::printError(Lang::UNABLE_TO_PARSER_YAML);
            }
        }
    }
}
