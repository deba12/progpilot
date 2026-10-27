<?php

/*
 * This file is part of ProgPilot, a static analyzer for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


namespace progpilot\Objects;

class MyFile extends MyOp
{
    private ?MyFile $includedFromMyFile = null;
    private ?MyFile $includedToMyFile = null;
    public string $baseDir;
    /**
     * @var string
     */
    public string $fileName;

    public function __construct(string $fullPathFileName, string $baseDir, int $fakeLine, int $fakeColumn)
    {
        parent::__construct($fullPathFileName, $fakeLine, $fakeColumn);
        $this->baseDir = $baseDir;
        $this->fileName = substr($fullPathFileName, strlen($baseDir) + 1);
    }

    public function setIncludedToMyfile(MyFile $myFileTo): void
    {
        $this->includedToMyFile = $myFileTo;
    }

    public function getIncludedToMyfile(): ?MyFile
    {
        return $this->includedToMyFile;
    }

    public function setIncludedFromMyfile(MyFile $myFileFrom): void
    {
        $this->includedFromMyFile = $myFileFrom;
    }

    public function getIncludedFromMyfile(): ?MyFile
    {
        return $this->includedFromMyFile;
    }

    public function printStdout(mixed $context = null): void
    {
        echo "file " . $this->getName() . "\n";
        $includeFile = $this->getIncludedFromMyfile();
        while (!is_null($includeFile)) {
            echo "included from " . $includeFile->getName() . "\n";
            $includeFile = $includeFile->getIncludedFromMyfile();
        }
        $includeFile = $this->getIncludedToMyfile();
        while (!is_null($includeFile)) {
            echo "included to " . $includeFile->getName() . "\n";
            $includeFile = $includeFile->getIncludedToMyfile();
        }
    }
}
