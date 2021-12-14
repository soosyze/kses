# Soosyze kses (kses strips evil scripts)

[![Build Status](https://github.com/soosyze/kses/workflows/Tests/badge.svg?branch=master)](https://github.com/soosyze/kses/actions?query=branch:master "Tests")
[![Coverage Status](https://coveralls.io/repos/github/soosyze/kses/badge.svg?branch=master)](https://coveralls.io/github/soosyze/kses?branch=master "Coveralls")
[![GitHub](https://img.shields.io/github/license/soosyze/kses)](https://github.com/soosyze/kses/blob/master/LICENSE "LICENSE")
[![Packagist](https://img.shields.io/packagist/v/soosyze/kses.svg)](https://packagist.org/packages/soosyze/kses "Packagist")
[![PHP from Packagist](https://img.shields.io/packagist/php-v/soosyze/kses.svg)](#version-php)

## Introduction

Welcome to kses - an HTML/XHTML filter written in PHP. It removes all unwanted HTML elements and attributes, no matter how malformed HTML input you give it.
Checks on attribute values. Can be used to avoid Cross-Site Scripting (XSS), Buffer Overflows and Denial of Service attacks, among other things.

Pass the tests of protection against XSS attacks proposed by the [OWASP® Foundation](https://owasp.org/www-community/xss-filter-evasion-cheatsheet).

## Features

Some of kses current features are:

* It will only allow the HTML elements and attributes that it was explicitly told to allow,
* Element and attribute names are case-insensitive (`a href` vs `A HREF`),
* It will understand and process whitespace correctly,
* Attribute values can be surrounded with quotes, apostrophes or nothing,
* It will accept valueless attributes with just names and no values (selected),
* It will accept XHTML's closing ` /` marks,
* Attribute values that are surrounded with nothing will get quotes to avoid producing non-W3C conforming HTML,
  * Example : `<a href=http://foo.com>` works but isn't valid HTML.
* It handles lots of types of malformed HTML, by interpreting the existing code the best it can and then rebuilding new code from it.
  That's a better approach than trying to process existing code, as you're bound to forget about some weird special case somewhere. It handles problems like never-ending quotes and tags gracefully,
* It will remove additional `<` and `>` characters that people may try to sneak in somewhere,
* It supports checking attribute values for minimum/maximum length and minimum/maximum value, to protect against Buffer Overflows and Denial of Service attacks against WWW clients and various servers.
  You can stop `<iframe src= width= height=>` from having too high values for width and height, for instance,
* It has got a system for allowed listing URL protocols. You can say that attribute values may only start with `http:`, `https:`, `ftp:` and `gopher:`, but no other URL protocols (`javascript:`, `java:`, `about:`, `telnet:`..). 
  The functions that do this work handle whitespace, upper/lower case, HTML entities (`jav&#97;script:`) and repeated entries (`javascript:javascript:alert(57)`),
* It also normalizes HTML entities as a nice side effect,
* It removes Netscape 4's JavaScript entities `&{alert(57)};`,
* It handles `NULL` bytes and Opera's `chr(173)` whitespace characters,
* Provides allowlists of tag and protocol.

## Requirements

### Version PHP

| Version PHP     | Soosyze Kses 3.x |
|-----------------|------------------|
| <= 7.1          | ✗ Unsupported    |
| 7.2 / 7.3 / 7.4 | ✓ Supported      |
| 8.0 / 8.1       | ✓ Supported      |

## Installation

### Composer

To install **Kses** via Composer you must have the installer or the binary file [Composer](https://getcomposer.org/download/)

Go to your project directory, open a command prompt and run the following command:
```sh
composer require soosyze/kses --no-dev
```

Or, if you use the binary file,
```sh
php composer.phar require soosyze/kses --no-dev
```

## Use It

It's very easy to use kses in your own PHP web application! Basic usage looks like this:

```php
<?php

require __DIR__ . '/vendor/autoload.php';

use Kses\Kses;

$allowedTags = [
    'a'  => [
        'href'  => 1,
        'title' => 1
    ],
    'b'  => [],
    'br' => [],
    'i'  => [],
    'p'  => [
        'align' => 1
    ]
];

$allowedProtocols = [ 'http', 'https' ];

$xss = new Kses($allowed, $allowedProtocols);

$xss->filter('
    <h1>Lorem ipsum</h1>
    <p>Quisque sed ligula pulvinar, tempor dolor sit amet, placerat nisl.</p>
');

// Lorem ipsum
// <p>Quisque sed ligula pulvinar, tempor dolor sit amet, placerat nisl.</p>
```

This definition of `$allowed` means that only the elements `b`, `i`, `a`, `p` and `br` are allowed (along with their closing tags `/b`, `/i`, `/a`, `/p` and `/br`).
`b`, `i` and `br` may not have any attributes.
`a` may only have the attributes `href` and `title`, while `p` may only have the attribute `align`.
You can list the elements and attributes in the array in any mixture of upper and lower case. kses will also recognize HTML code that uses both lower and upper case.

It's important to select the right allowed attributes, so you won't open up an XSS hole by mistake.
Some important attributes that you mustn't allow include but are not limited to:

* Style,
* All intrinsic events attributes (`onMouseOver` and so `on`, `on*` really).

It's also important to note that kses HTML input must be cleaned of all slashes coming from magic quotes.
If the rest of your code requires these slashes to be present, you can always add them again after calling kses with a simple `addslashes()` call.

## Use It with allowlist

Authorization lists for tags and protocols are available :

* [KsesAllowedList::getProtocols();](src/KsesAllowedList.php#L7), list of default protocols,
* [KsesAllowedList::getTags();](src/KsesAllowedList.php#L31), list of default tags,
* [KsesAllowedList::getTagsAdmin()](src/KsesAllowedList.php#L119).

```php
<?php

require __DIR__ . '/vendor/autoload.php';

use Kses\Kses;
use Kses\KsesAllowedList;

$xss = new Kses();
/**
 * Similar to :
 * $xss = new Kses(KsesAllowedList::getTags(), KsesAllowedList::getProtocols());
 */

$xss->filter('<SCRIPT SRC=http://xss.rocks/xss.js></SCRIPT>');
// Result : ''

$xss->filter('<IMG SRC="javascript:alert(\'XSS\');">');
// Result : '<IMG src="alert(\'XSS\');">'

$xss->filter('\<a onmouseover=alert(document.cookie)\>xxs link\</a\>');
// Result : '\<a>xxs link\</a>'
```

### kses attribute value checks

As you've probably already read in the README file, an $allowed_html array normally looks like this:

```php
$allowed = [
    'a'  => [
        'href'  => 1,
        'title' => 1
    ],
    'b'  => [],
    'br' => [],
    'i'  => [],
    'p'  => [
        'align' => 1
    ]
];
```

This sets what elements and attributes are allowed.

From kses 0.2.0, you can also perform some checks on the attribute values. You do it like this:

```php
$allowed = [
    'a'    => [
        'href'  => [
            'maxlen' => 100
        ],
        'title' => 1
    ],
    'b'    => [],
    'br'   => [],
    'i'    => [],
    'p'    => [
        'align' => 1
    ],
    'font' => [
        'size' => [
            'maxval' => 20
        ]
    ]
];
```

This means that kses should perform the maxlen check with the value 100 on the `<a href=>` value, as well as the maxval check with the value 20 on the `<font size=>` value.

The currently implemented checks (with more to come) are **maxlen**, **maxval**, **minlen**, **minval** and **valueless**.

### maxlen

'maxlen' checks that the length of the attribute value is not greater than the given value.
It is helpful against Buffer Overflows in WWW clients and various servers on the Internet.
In my example above, it would mean that `<a href='ftp://ftp.v1ct1m.com/AAAA..thousands_of_A's...'>` wouldn't be accepted.

Of course, this problem is even worse if you put that long URL in a `<frame>` tag instead, so the WWW client will fetch it automatically without a user having to click it.

### maxval

**maxval** checks that the attribute value is an integer greater than or equal to zero, that it doesn't have an unreasonable amount of zeroes or whitespace (to avoid Buffer Overflows), and that it is not greater than the given value.
In my example above, it would mean that `<font size='20'>` is accepted but `<font size='21'>` is not.
This check helps against Denial of Service attacks against WWW clients.

One example of this DoS problem is `<iframe src="http://some.web.server/" width="20000" height="2000">`, which makes some client machines completely overloaded.

### minlen and minval

**minlen** and **minval** works the same as **maxlen** and **maxval**, except that they check for minimum lengths and values instead of maximum ones.

### valueless

**valueless** checks if an attribute has a value (like `<a href="blah">`) or not (`<option selected>`).
If the given value is a "y" or a "Y", the attribute must not have a value to be accepted.
If the given value is an "n" or an "N", the attribute must have a value.
Note that `<a href="">` is considered to have a value, so there's a difference between valueless attributes and attribute values with the length zero.

You can combine more than one check, by putting one after the other in the inner array.

### Allowed listed URL protocols

By default Kses loads with its own list of protocols:
* ftp, http, https, irc, news, nntp, rtsp, sftp, ssh, tel, telnet, webcal.

Pretty reasonable, but anyone who wants to change it just calls the `setAllowedProtocols()` or `addAlloweProtocol()` function with a third parameter, like this:

```php
$xss = new Kses();

$xss->setAllowedProtocols(['http', 'https']);

$xss->addAlloweProtocol('news');
```

Note that you shouldn't include any colon after http or other protocol names.

## Bug reports

The first authors of Kses no longer seem to maintain the code. Used by Wordpress and Drupal, we will closely monitor their implementations.

If you have found any security problems (particularly XSS, naturally) in kses, please contact Soosyze CMS team privately on Discord, Mastodon or the Forum so he can correct it before you or someone else tells the public about it.

(No, it's not a security problem in kses if some program that uses it allows a bad attribute, silly. If kses is told to accept the element body with the attributes style and onLoad, it will accept them, even if that's a really bad idea, securitywise.)

## The first authors of Kses

* **Ulf Harnhammar**, (main coder, project leader) metaur at users dot sourceforge dot net http://www.advogato.org/person/metaur/
* **Richard R. Vásquez, Jr.**, (coder of object-oriented kses) contact him at http://chaos.org/contact/

### Thanks to

* **Peter Valach**, code review and feature suggestions
* **Simon Cornelius P. Umacob**, testing
* **Dirk Haun**, feature suggestion
* **Hendy Irawan**, bug report and documentation suggestion
* **dude21**, feature suggestion
* **Christian Bolstad**, documentation suggestion
* **SourceForge**, project hosting

Thanks also go to a lot of people who posted to the Bugtraq and mailing lists about XSS or HTML filters. They gave us some valuable insights.

## License

The program is released under the terms of the GNU General Public License.
You should look into what that means, before using kses in your programs.
You can find the full text of the license in the [file LICENSE](/LICENSE).