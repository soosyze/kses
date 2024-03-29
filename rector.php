<?php

declare(strict_types=1);

use Rector\Config\RectorConfig;
use Rector\Core\ValueObject\PhpVersion;
use Rector\Set\ValueObject\SetList;

return static function (RectorConfig $rectorConfig): void {
    // paths to refactor; solid alternative to CLI arguments
    $rectorConfig->paths([
        __DIR__ . '/src',
        __DIR__ . '/tests'
    ]);

    // is your PHP version different from the one your refactor to? [default: your PHP version], uses PHP_VERSION_ID format
    $rectorConfig->phpVersion(PhpVersion::PHP_72);

    // Define what rule sets will be applied
    $rectorConfig->sets([SetList::CODE_QUALITY]);

    // Path to phpstan with extensions, that PHPSTan in Rector uses to determine types
    $rectorConfig->phpstanConfig(__DIR__ . '/phpstan.neon.dist');
};
