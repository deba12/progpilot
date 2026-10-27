<?php

/*
 * This file is part of ProgPilot, a static analyzer for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


namespace progpilot;

class Context extends ContextInternalApi
{
    #[\Override]
    public function setPrettyPrint(bool $bool): void
    {
        $this->prettyPrint = $bool;
    }

    public function getPrettyPrint(): bool
    {
        return $this->prettyPrint;
    }

    #[\Override]
    public function setDebugMode(bool $bool): void
    {
        $this->debugMode = $bool;
    }

    public function isDebugMode(): bool
    {
        return $this->debugMode;
    }

    #[\Override]
    public function setMaxDefinitions(int $maxDefinitions): void
    {
        $this->maxDefinitions = $maxDefinitions;
    }

    public function getMaxDefinitions(): int
    {
        return $this->maxDefinitions;
    }

    #[\Override]
    public function setMaxFileAnalysisDuration(int $maxFileAnalysisDuration): void
    {
        $this->maxFileAnalysisDuration = $maxFileAnalysisDuration;
    }

    public function getMaxFileAnalysisDuration(): int
    {
        return $this->maxFileAnalysisDuration;
    }

    #[\Override]
    public function setMaxFileSize(int $maxFileSize): void
    {
        $this->maxFileSize = $maxFileSize;
    }

    public function getMaxFileSize(): int
    {
        return $this->maxFileSize;
    }

    #[\Override]
    public function setMaxMemory(int $maxMemory): void
    {
        $this->maxMemory = $maxMemory;
    }

    public function getMaxMemory(): int
    {
        return $this->maxMemory;
    }

    public function getAnalyzeIncludes(): bool
    {
        return $this->analyzeIncludes;
    }

    #[\Override]
    public function setAnalyzeIncludes(bool $analyzeIncludes): void
    {
        $this->analyzeIncludes = $analyzeIncludes;
    }

    public function setConfiguration(string $file): void
    {
        $this->configurationFile = $file;
    }

    public function getConfiguration(): ?string
    {
        return $this->configurationFile;
    }
}
