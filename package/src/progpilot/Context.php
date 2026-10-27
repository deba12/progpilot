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
    public function setPrettyPrint($bool): void
    {
        $this->prettyPrint = $bool;
    }

    public function getPrettyPrint()
    {
        return $this->prettyPrint;
    }

    public function setDebugMode($bool): void
    {
        $this->debugMode = $bool;
    }

    public function isDebugMode()
    {
        return $this->debugMode;
    }

    public function setMaxDefinitions($maxDefinitions): void
    {
        $this->maxDefinitions = $maxDefinitions;
    }

    public function getMaxDefinitions()
    {
        return $this->maxDefinitions;
    }

    public function setMaxFileAnalysisDuration($maxFileAnalysisDuration): void
    {
        $this->maxFileAnalysisDuration = $maxFileAnalysisDuration;
    }

    public function getMaxFileAnalysisDuration()
    {
        return $this->maxFileAnalysisDuration;
    }

    public function setMaxFileSize($maxFileSize): void
    {
        $this->maxFileSize = $maxFileSize;
    }

    public function getMaxFileSize()
    {
        return $this->maxFileSize;
    }

    public function setMaxMemory($maxMemory): void
    {
        $this->maxMemory = $maxMemory;
    }

    public function getMaxMemory()
    {
        return $this->maxMemory;
    }

    public function getAnalyzeIncludes()
    {
        return $this->analyzeIncludes;
    }

    public function setAnalyzeIncludes($analyzeIncludes): void
    {
        $this->analyzeIncludes = $analyzeIncludes;
    }

    public function setConfiguration($file): void
    {
        $this->configurationFile = $file;
    }

    public function getConfiguration()
    {
        return $this->configurationFile;
    }
}
