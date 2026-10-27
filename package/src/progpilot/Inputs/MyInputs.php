<?php

/*
 * This file is part of ProgPilot, a static analyzer for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


declare(strict_types=1);

namespace progpilot\Inputs;

use progpilot\Lang;
use progpilot\Utils;

class MyInputs extends MyInputsInternalApi
{
    public function getFolder(): ?string
    {
        return $this->folder;
    }

    public function getFile(): ?string
    {
        return $this->file;
    }

    public function getCode(): ?string
    {
        return $this->code;
    }

    public function setFolder(string $folder): void
    {
        $this->folder = $folder;
    }

    public function setFile(string $file): void
    {
        $this->file = $file;
    }

    public function setCode(?string $code): void
    {
        $this->code = $code;
    }

    public function getDev(): bool
    {
        return $this->dev;
    }

    public function setDev(bool $dev): void
    {
        $this->dev = $dev;

        if ($this->dev) {
            $sanitizersfile = __DIR__ . "/../../uptodate_data/php/dev/sanitizers.json";
            $this->readSanitizersFile($sanitizersfile);

            $sinksfile = __DIR__ . "/../../uptodate_data/php/dev/sinks.json";
            $this->readSinksFile($sinksfile);

            $sourcesfile = __DIR__ . "/../../uptodate_data/php/dev/sources.json";
            $this->readSourcesFile($sourcesfile);

            $validatorsfile = __DIR__ . "/../../uptodate_data/php/dev/validators.json";
            $this->readValidatorsFile($validatorsfile);

            $customsfile = __DIR__ . "/../../uptodate_data/php/dev/rules.json";
            $this->readCustomFile($customsfile);
        }
    }

    /**
     * @param list<string>|null $files
     */
    public function addSources(?array $files): void
    {
        if (is_array($files)) {
            foreach ($files as $file) {
                $this->readSourcesFile($file);
            }
        } else {
            $this->readSourcesFile($files);
        }
    }

    /**
     * @param list<string> $files
     */
    public function setSources(array $files): void
    {
        $this->overwrittenSources = true;
        $this->sources = [];
        $this->addSources($files);
    }

    /**
     * @return list<MySource>
     */
    public function getSources(): array
    {
        return $this->sources;
    }

    /**
     * @param string|list<string>|null $files
     */
    public function addSinks(string|array|null $files): void
    {
        if (is_array($files)) {
            foreach ($files as $file) {
                $this->readSinksFile($file);
            }
        } else {
            $this->readSinksFile($files);
        }
    }

    /**
     * @return list<MySink>
     */
    public function getSinks(): array
    {
        return $this->sinks;
    }

    /**
     * @param string|list<string>|null $files
     */
    public function setSinks(string|array|null $files): void
    {
        $this->overwrittenSinks = true;
        $this->sinks = [];
        $this->addSinks($files);
    }

    /**
     * @param string|list<string>|null $files
     */
    public function addValidators(string|array|null $files): void
    {
        if (is_array($files)) {
            foreach ($files as $file) {
                $this->readValidatorsFile($file);
            }
        } else {
            $this->readValidatorsFile($files);
        }
    }

    /**
     * @param string|list<string>|null $files
     */
    public function setValidators(string|array|null $files): void
    {
        $this->overwrittenValidators = true;
        $this->validators = [];
        $this->addValidators($files);
    }

    /**
     * @return list<MyValidator>
     */
    public function getValidators(): array
    {
        return $this->validators;
    }

    /**
     * @param string|list<string>|null $files
     */
    public function addSanitizers(string|array|null $files): void
    {
        if (is_array($files)) {
            foreach ($files as $file) {
                $this->readSanitizersFile($file);
            }
        } else {
            $this->readSanitizersFile($files);
        }
    }

    /**
     * @param string|list<string>|null $files
     */
    public function setSanitizers(string|array|null $files): void
    {
        $this->overwrittenSanitizers = true;
        $this->sanitizers = [];
        $this->addSanitizers($files);
    }

    /**
     * @return list<MySanitizer>
     */
    public function getSanitizers(): array
    {
        return $this->sanitizers;
    }

    /**
     * @param string|list<string>|null $files
     */
    public function addCustomRules(string|array|null $files): void
    {
        if (is_array($files)) {
            foreach ($files as $file) {
                $this->readCustomFile($file);
            }
        } else {
            $this->readCustomFile($files);
        }
    }

    /**
     * @param string|list<string>|null $files
     */
    public function setCustomRules(string|array|null $files): void
    {
        $this->overwrittenCustomRules = true;
        $this->customRules = [];
        $this->addCustomRules($files);
    }

    /**
     * @return list<MyCustomRule>
     */
    public function getCustomRules(): array
    {
        return $this->customRules;
    }

    public function setResolvedIncludes(?string $resolvedIncludes): void
    {
        if (is_null($resolvedIncludes)) {
            return;
        }

        if (!file_exists($resolvedIncludes)) {
            Utils::printError(
                Lang::FILE_DOESNT_EXIST . " (" . Utils::encodeCharacters($resolvedIncludes) . ")"
            );
        }

            $outputJson = file_get_contents($resolvedIncludes);
            $parsedJson = json_decode($outputJson);

        if (isset($parsedJson->{'includes'})) {
            $includes = $parsedJson->{'includes'};
            foreach ($includes as $include) {
                if (
                    !isset($include->{'line'})
                    || !isset($include->{'column'})
                    || !isset($include->{'source_file'})
                    || !isset($include->{'value'})
                ) {
                    Utils::printError(Lang::FORMAT_INCLUDES);
                }

                if (realpath($include->{'source_file'})) {
                    $line = $include->{'line'};
                    $column = $include->{'column'};
                    $sourceFile = realpath($include->{'source_file'});
                    $value = $include->{'value'};

                    $myInclude = new MyInclude($line, $column, $sourceFile, $value);
                    if (!in_array($myInclude, $this->resolvedIncludesAnalysis, true)) {
                        $this->resolvedIncludesAnalysis[] = $myInclude;
                    }
                }
            }
        } else {
            Utils::printError(Lang::FORMAT_INCLUDES);
        }
    }

    /**
     * @return list<MyVuln>
     */
    public function getFalsePositives(): array
    {
        return $this->falsePositivesAnalysis;
    }

    /**
     * @param string|list<array<string, mixed>>|null $falsePositives
     */
    public function setFalsePositives(string|array|null $falsePositives): void
    {
        $this->readFalsePositives($falsePositives);
    }

    /**
     * @return list<string|bool>
     */
    public function getInclusions(): array
    {
        return $this->includesFilesAnalysis;
    }

    /**
     * @return list<string|bool>
     */
    public function getExclusions(): array
    {
        return $this->excludesFilesAnalysis;
    }

    /**
     * @param string|array<mixed>|null $exclusions a file name containing the exclusions or the exclusions themselves
     */
    public function setExclusions(string|array|null $exclusions): void
    {
        $this->excludesFilesAnalysis = [];
        $this->addExclusions($exclusions);
    }

    /**
     * @param string|array<mixed>|null $inclusions a file name containing the inclusions or the inclusions themselves
     */
    public function setInclusions(string|array|null $inclusions): void
    {
        $this->includesFilesAnalysis = [];
        $this->addInclusions($inclusions);
    }

    /**
     * @param string|array<mixed>|null $exclusions a file name containing the exclusions or the exclusions themselves
     */
    public function addExclusions(string|array|null $exclusions): void
    {
        if (!is_null($exclusions)) {
            if (is_string($exclusions)) {
                $this->readExcludesFile($exclusions);
            } else {
                foreach ($exclusions as $excludeFile) {
                    if (is_string($excludeFile) && !in_array($excludeFile, $this->excludesFilesAnalysis, true)) {
                        $this->excludesFilesAnalysis[] = $excludeFile;
                    }
                }
            }
        }
    }

    /**
     * @param string|array<mixed>|null $inclusions a file name containing the inclusions or the inclusions themselves
     */
    public function addInclusions(string|array|null $inclusions): void
    {
        if (!is_null($inclusions)) {
            if (is_string($inclusions)) {
                $this->readIncludesFile($inclusions);
            } else {
                foreach ($inclusions as $includeFile) {
                    if (is_string($includeFile) && !in_array($includeFile, $this->includesFilesAnalysis, true)) {
                        $this->includesFilesAnalysis[] = $includeFile;
                    }
                }
            }
        }
    }
}
