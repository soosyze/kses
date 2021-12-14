<?php

declare(strict_types=1);

/**
 * @license http://www.gnu.org/licenses/gpl.html GPLv2
 * Based on kses by Ulf Harnhammar, see http://sourceforge.net/projects/kses.
 * @copyright (c) 2002, 2003, 2005  Ulf Harnhammar
 */

namespace Kses;

/**
 * HTML/XHTML filter that only allows some elements and attributes.
 * Can be used to avoid Cross-Site Scripting (XSS).
 *
 * @see https://owasp.org/www-community/xss-filter-evasion-cheatsheet
 */
class Kses
{
    /**
     * @var array
     */
    protected $allowedHtml = [];

    /**
     * @var array
     */
    protected $allowedProtocols = [];

    public function __construct(
        array $allowedHtml = [],
        array $allowedProtocols = []
    ) {
        $this->allowedHtml      = empty($allowedHtml)
            ? KsesAllowedList::getTags()
            : $allowedHtml;
        $this->allowedProtocols = empty($allowedProtocols)
            ? KsesAllowedList::getProtocols()
            : $allowedProtocols;
    }

    public function setAllowedTags(array $allowedTags): self
    {
        $this->allowedHtml = $allowedTags;

        return $this;
    }

    public function addAllowedTag(string $allowedTag, array $attr = []): self
    {
        $this->allowedHtml[ $allowedTag ] = $attr;

        return $this;
    }

    public function setAllowedProtocols(array $allowedProtocols): self
    {
        $this->allowedProtocols = $allowedProtocols;

        return $this;
    }

    public function addAllowedProtocol(string $allowedProtocol): self
    {
        $this->allowedProtocols[] = $allowedProtocol;

        return $this;
    }

    /**
     * This function makes sure that only the allowed HTML element names, attribute
     * names and attribute values plus only sane HTML entities will occur in
     * $str. You have to remove any slashes from PHP's magic quotes before you
     * call this function.
     *
     * @param string $str
     *
     * @return string An XSS safe version of $string,
     *                or an empty string if $string is not valid UTF-8.
     */
    public function filter(string $str): string
    {
        if (!$this->isUtf8($str)) {
            return '';
        }

        /* Removes any NULL characters in $str. */
        $str = str_replace(chr(0), '', $str);

        /* Remove Netscape 4 JS entities. */
        $str = preg_replace('%&\s*\{[^}]*(\}\s*;?|$)%', '', $str) ?? '';

        $str = self::normalizeEntities($str);

        return (string) preg_replace_callback(
            '%
            (
            <(?=[^a-zA-Z!/])  # a lone <
            |                 # or
            <!--.*?-->        # a comment
            |                 # or
            <[^>]*(>|$)       # a string that starts with a <, up until the > or the end of the string
            |                 # or
            >                 # just a >
            )%x',
            function (array $match): string {
                return $this->stripTags($match);
            },
            $str
        );
    }

    /**
     * @param string $str
     */
    protected function isUtf8(string $str): bool
    {
        if ($str === '') {
            return true;
        }
        /*
         * With the PCRE_UTF8 modifier 'u', preg_match() fails silently on strings
         * containing invalid UTF-8 byte sequences. It does not reject character
         * codes above U+10FFFF (represented by 4 or more octets), though.
         */
        return preg_match('/^./us', $str) === 1;
    }

    /**
     * This function does a lot of work. It rejects some very malformed things
     * like <:::>. It returns an empty string, if the element isn't allowed (look
     * ma, no strip_tags()!). Otherwise it splits the tag into an element and an
     * attribute list.
     */
    protected function stripTags(array $match): string
    {
        $str = $match[ 0 ];

        if (substr($str, 0, 1) !== '<') {
            /* We matched a lone ">" character. */
            return '&gt;';
        }
        if (strlen($str) === 1) {
            /* We matched a lone "<" character. */
            return '&lt;';
        }

        /* It's seriously malformed. */
        if (!preg_match('%^<\s*(/\s*)?([-a-zA-Z0-9]+)\s*([^>]*)>?|(<!--.*?-->)$%', $str, $matches)) {
            return '';
        }

        $slash    = trim($matches[ 1 ]);
        $tag      = &$matches[ 2 ];
        $attrList = &$matches[ 3 ];
        $comment  = &$matches[ 4 ];

        if ($comment) {
            $tag = '!--';
        }

        if (!isset($this->allowedHtml[ strtolower($tag) ])) {
            return '';
        }

        if ($comment) {
            return $comment;
        }

        /* They are using a not allowed HTML element. */
        if ($slash !== '') {
            return "</$tag>";
        }

        /* No attributes are allowed for closing elements. */
        return $this->stripAttributes("$slash$tag", $attrList);
    }

    /**
     * This function removes all attributes, if none are allowed for this element.
     * If some are allowed it calls combineAttributes() to split them further, and then it
     * builds up new HTML code from the data that combineAttributes() returns. It also
     * removes "<" and ">" characters, if there are any left. One more thing it
     * does is to check if the tag has a closing XHTML slash, and if it does,
     * it puts one in the returned code as well.
     *
     * @param string $tag
     * @param string $attr
     *
     * @return string
     */
    protected function stripAttributes(string $tag, string $attr): string
    {
        /* Is there a closing XHTML slash at the end of the attributes? */
        $xhtmlSlash = preg_match('%\s/\s*$%', $attr)
            ? ' /'
            : '';

        /* Are any attributes allowed at all for this element? */
        if (count($this->allowedHtml[ strtolower($tag) ]) === 0) {
            return "<$tag$xhtmlSlash>";
        }

        /* Split it. */
        $attrArr = $this->combineAttributes($attr);

        /* Go through $attrArr, and save the allowed attributes for this element in $attrList. */
        $attrList = '';

        $tagAllowed = strtolower($tag);

        foreach ($attrArr as $arrEach) {
            $current = $this->allowedHtml[ $tagAllowed ][ strtolower($arrEach[ 'name' ]) ] ?? null;

            if ($current === null) {
                /* The attribute is not allowed. */
                continue;
            }

            if (!is_array($current)) {
                $attrList .= ' ' . $arrEach[ 'whole' ];

                continue;
            }

            foreach ($current as $key => $value) {
                if (self::checkAttrVal(
                    $arrEach[ 'value' ],
                    $arrEach[ 'vless' ],
                    $key,
                    $value
                )) {
                    /* It passed them. */
                    $attrList .= ' ' . $arrEach[ 'whole' ];

                    break;
                }
            }
        }

        /* Remove any "<" or ">" characters. */
        $attrList = preg_replace('/[<>]/', '', $attrList) ?? '';

        return "<$tag$attrList$xhtmlSlash>";
    }

    /**
     * This function does a lot of work. It parses an attribute list into an array
     * with attribute data, and tries to do the right thing even if it gets weird
     * input. It will add quotes around attribute values that don't have any quotes
     * or apostrophes around them, to make it easier to produce HTML code that will
     * conform to W3C's HTML specification. It will also remove bad URL protocols
     * from attribute values.
     *
     * @param string $attr
     *
     * @return array
     */
    protected function combineAttributes(string $attr): array
    {
        $attrArr  = [];
        $mode     = 0;
        $attrName = '';

        /* Loop through the whole attribute list. */
        while (strlen($attr) !== 0) {
            /* Was the last operation successful? */
            $working = 0;

            switch ($mode) {
                /* Attribute name, href for instance. */
                case 0:

                    if (preg_match('/^([-a-zA-Z]+)/', $attr, $match)) {
                        $working  = 1;
                        $mode     = 1;
                        $attr     = preg_replace('/^[-a-zA-Z]+/', '', $attr) ?? '';
                        $attrName = strtolower($match[ 1 ]);
                    }

                    break;
                /* Equals sign or valueless ("selected"). */
                case 1:

                    if (preg_match('/^\s*=\s*/', $attr)) {
                        /* Equals sign. */
                        $working = 1;
                        $mode    = 2;
                        $attr    = preg_replace('/^\s*=\s*/', '', $attr) ?? '';

                        break;
                    }

                    if (preg_match('/^\s+/', $attr)) {
                        /* Valueless. */
                        $working = 1;
                        $mode    = 0;
                        $attr    = preg_replace('/^\s+/', '', $attr) ?? '';

                        $attrArr[] = [
                            'name'  => $attrName,
                            'value' => '',
                            'whole' => $attrName,
                            'vless' => 'y'
                        ];
                    }

                    break;
                /* Attribute value, a URL after href= for instance. */
                case 2:

                    if (preg_match('/^"([^"]*)"(\s+|$)/', $attr, $match)) {
                        /* "value" */
                        $working = 1;
                        $mode    = 0;
                        $attr    = preg_replace('/^"[^"]*"(\s+|$)/', '', $attr) ?? '';
                        $thisVal = $this->badProtocol($match[ 1 ]);

                        $attrArr[] = [
                            'name'  => $attrName,
                            'value' => $thisVal,
                            'whole' => "$attrName=\"$thisVal\"",
                            'vless' => 'n'
                        ];

                        break;
                    }

                    if (preg_match("/^'([^']*)'(\s+|$)/", $attr, $match)) {
                        /* 'value' */
                        $working = 1;
                        $mode    = 0;
                        $attr    = preg_replace("/^'[^']*'(\s+|$)/", '', $attr) ?? '';
                        $thisVal = $this->badProtocol($match[ 1 ]);

                        $attrArr[] = [
                            'name'  => $attrName,
                            'value' => $thisVal,
                            'whole' => "$attrName='$thisVal'",
                            'vless' => 'n'
                        ];

                        break;
                    }

                    if (preg_match("%^([^\s\"']+)(\s+|$)%", $attr, $match)) {
                        /* value */
                        $working = 1;
                        $mode    = 0;
                        /* We add quotes to conform to W3C's HTML spec. */
                        $attr    = preg_replace("%^[^\s\"']+(\s+|$)%", '', $attr) ?? '';
                        $thisVal = $this->badProtocol($match[ 1 ]);

                        $attrArr[] = [
                            'name'  => $attrName,
                            'value' => $thisVal,
                            'whole' => "$attrName=\"$thisVal\"",
                            'vless' => 'n'
                        ];
                    }

                    break;
            }

            if ($working === 0) {
                /* Not well formed, remove and try again. */
                $attr = self::htmlError($attr);
                $mode = 0;
            }
        }

        if ($mode === 1) {
            /* Special case, for when the attribute list ends with a valueless. */
            /* Attribute like "selected". */
            $attrArr[] = [
                'name'  => $attrName,
                'value' => '',
                'whole' => $attrName,
                'vless' => 'y'
            ];
        }

        return $attrArr;
    }

    /**
     * This function performs different checks for attribute values. The currently
     * implemented checks are "maxlen", "minlen", "maxval", "minval" and "valueless"
     * with even more checks to come soon.
     *
     * @param string               $value
     * @param string               $vless
     * @param string               $checkName
     * @param numeric|string|array $checkValue
     *
     * @return boolean
     */
    protected static function checkAttrVal(
        string $value,
        string $vless,
        string $checkName,
        $checkValue
    ): bool {
        switch ($checkName) {
            case 'maxlen':
                if (!\is_numeric($checkValue)) {
                    throw new \InvalidArgumentException('maxlen must be of type numeric, ' . gettype($checkValue) . ' given');
                }
                /*
                 * The maxlen check makes sure that the attribute value has a length not
                 * greater than the given value. This can be used to avoid Buffer Overflows
                 * in WWW clients and various Internet servers.
                 */
                return strlen($value) <= $checkValue;

            case 'minlen':
                if (!\is_numeric($checkValue)) {
                    throw new \InvalidArgumentException('maxlen must be of type numeric, ' . gettype($checkValue) . ' given');
                }
                /*
                 * The minlen check makes sure that the attribute value has a length not
                 * smaller than the given value.
                 */
                return strlen($value) >= $checkValue;

            case 'maxval':
                if (!\is_numeric($checkValue)) {
                    throw new \InvalidArgumentException('maxlen must be of type numeric, ' . gettype($checkValue) . ' given');
                }
                /*
                 * The maxval check does two things: it checks that the attribute value is
                 * an integer from 0 and up, without an excessive amount of zeroes or
                 * whitespace (to avoid Buffer Overflows). It also checks that the attribute
                 * value is not greater than the given value.
                 * This check can be used to avoid Denial of Service attacks.
                 */
                if (!preg_match('/^\s{0,6}\d{1,6}\s{0,6}$/', $value)) {
                    return false;
                }

                return $value <= $checkValue;

            case 'minval':
                if (!\is_numeric($checkValue)) {
                    throw new \InvalidArgumentException('maxlen must be of type numeric, ' . gettype($checkValue) . ' given');
                }
                /*
                 * The minval check checks that the attribute value is a positive integer,
                 * and that it is not smaller than the given value.
                 */
                if (!preg_match('/^\s{0,6}\d{1,6}\s{0,6}$/', $value)) {
                    return false;
                }

                return $value >= $checkValue;

            case 'valueless':
                if (!\is_string($checkValue)) {
                    throw new \InvalidArgumentException('valueless must be of type string, ' . gettype($checkValue) . ' given');
                }
                /*
                 * The valueless check checks if the attribute has a value
                 * (like <a href="blah">) or not (<option selected>). If the given value
                 * is a "y" or a "Y", the attribute must not have a value.
                 * If the given value is an "n" or an "N", the attribute must have one.
                 */
                return strtolower($checkValue) === $vless;

            case 'content':
                if (!\is_array($checkValue)) {
                    throw new \InvalidArgumentException('content must be of type array, ' . gettype($checkValue) . ' given');
                }
                foreach ($checkValue as $check) {
                    $str     = preg_quote($check, '/');
                    $pattern = strtr($str, [ '%' => '.*' ]);

                    if (preg_match("/$pattern/", $value)) {
                        return true;
                    }
                }

                return false;
            default:
                return true;
        }
    }

    /**
     * This function removes all non-allowed protocols from the beginning of
     * $str. It ignores whitespace and the case of the letters, and it does
     * understand HTML entities. It does its work in a while loop, so it won't be
     * fooled by a string like "javascript:javascript:alert(57)".
     */
    protected function badProtocol(string $str): string
    {
        /* Removes any NULL characters in $str. */
        $str = str_replace(chr(0), '', $str);

        /* Deals with Opera "feature". */
        $string = preg_replace('/\xad+/', '', $str)  ?? '';
        $string .= 'a';

        while ($str !== $string) {
            $string = $str;

            /**
             * This function searches for URL protocols at the beginning of $string, while
             * handling whitespace and HTML entities.
             */
            $str = preg_replace_callback(
                '/^((&[^;]*;|[\sA-Za-z0-9])*)(:|&#58;|&#[Xx]3[Aa];)\s*/',
                function (array $str) : string {
                    return $this->badProtocolOnce($str);
                },
                $str
            ) ?? '';
        }

        return $str;
    }

    /**
     * This function deals with parsing errors in combineAttributes(). The general plan is
     * to remove everything to and including some whitespace, but it deals with
     * quotes and apostrophes as well.
     */
    protected static function htmlError(string $str): string
    {
        return preg_replace('/
        ^
        (
        "[^"]*("|$)     # - a string that starts with a double quote, up until the next double quote or the end of the string
        |               # or
        \'[^\']*(\'|$)| # - a string that starts with a quote, up until the next quote or the end of the string
        |               # or
        \S              # - a non-whitespace character
        )*              # any number of the above three
        \s*             # any number of whitespaces
        /x', '', $str) ?? '';
    }

    /**
     * This function processes URL protocols, checks to see if they're in the white-
     * list or not, and returns different data depending on the answer.
     */
    protected function badProtocolOnce(array $str): string
    {
        $string = self::deleteEntities($str[ 1 ]);
        $string = preg_replace('/\s/', '', $string) ?? '';
        /* Deals with Opera "feature". */
        $string = preg_replace('/\xad+/', '', $string) ?? '';
        $string = strtolower($string);

        return in_array($string, $this->allowedProtocols)
            ? "$string:"
            : '';
    }

    /**
     * This function normalizes HTML entities. It will convert "AT&T" to the correct
     * "AT&amp;T", "&#00058;" to "&#58;", "&#XYZZY;" to "&amp;#XYZZY;" and so on.
     */
    protected static function normalizeEntities(string $str): string
    {
        /* Disarm all entities by converting & to &amp; */
        $str = str_replace('&', '&amp;', $str);

        /* Entités numériques décimales. */
        $str = preg_replace(
            '/&amp;#(\d+;)/',
            '&#\1',
            $str
        ) ?? '';

        /* Hexadecimal numeric entities. */
        $str = preg_replace(
            '/&amp;#[Xx]0*((?:[0-9A-Fa-f]{2})+;)/',
            '&#x\1',
            $str
        ) ?? '';

        /* Named entities. */
        return preg_replace(
            '/&amp;([A-Za-z][A-Za-z0-9]*;)/',
            '&\1',
            $str
        ) ?? '';
    }

    /**
     * This function delete numeric HTML entities (&#65; and &#x41;). It doesn't
     * do anything with other entities like &auml;, but we don't need them in the
     * URL protocol whitelisting system anyway.
     */
    protected static function deleteEntities(string $str): string
    {
        $str = preg_replace('/&#(\d+);/', '', $str) ?? '';

        return preg_replace('/&#[Xx]([0-9A-Fa-f]+);/', '', $str) ?? '';
    }
}
