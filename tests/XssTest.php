<?php

namespace Soosyze\Kses\Tests;

use Soosyze\Kses\AllowedList;
use Soosyze\Kses\Xss;

class XssTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @var Xss
     */
    protected $xss;

    protected function setUp(): void
    {
        $this->xss = new Xss(AllowedList::getTagsAdmin());
    }

    public function testCorrectTag(): void
    {
        $html   = 'kses \'kses\' /kses "kses" kses \\kses\\';
        $filter = $this->xss->filter($html);

        $this->assertEquals($html, $filter);
    }

    public function testCorrectTag2(): void
    {
        $filter = (new Xss)->filter('kses<br>');

        $this->assertEquals($filter, 'kses<br>');
    }

    public function testCorrectTag3(): void
    {
        $filter = $this->xss
            ->addAllowedTag('br')
            ->filter('kses <BR >');

        $this->assertEquals($filter, 'kses <BR>');
    }

    public function testCorrectTag4(): void
    {
        $filter = $this->xss
            ->addAllowedTag('br')
            ->filter('kses > 5 <br>');

        $this->assertEquals($filter, 'kses &gt; 5 <br>');
    }

    public function testCorrectTag5(): void
    {
        $filter = $this->xss
            ->addAllowedTag('br')
            ->filter('kses < br');

        $this->assertEquals($filter, 'kses &lt; br');
    }

    public function testCorrectTag6(): void
    {
        $filter = $this->xss
            ->setAllowedTags([
                'br' => [],
                'a'  => []
            ])
            ->filter('kses <a href=5>');

        $this->assertEquals($filter, 'kses <a>');
    }

    public function testCorrectTag7(): void
    {
        $filter = $this->xss
            ->filter('kses <a href=5>');

        $this->assertEquals($filter, 'kses <a href="5">');
    }

    public function testCorrectTag8(): void
    {
        $filter = $this->xss
            ->filter('kses <a href>');

        $this->assertEquals($filter, 'kses <a href>');
    }

    public function testCorrectTag9(): void
    {
        $filter = $this->xss
            ->filter('kses <a href href=5 href=\'5\' href="5" dummy>');

        $this->assertEquals($filter, 'kses <a href href="5" href=\'5\' href="5">');
    }

    public function testCorrectTag10(): void
    {
        $filter = $this->xss
            ->filter('kses <a href="kses\\\\kses">');

        $this->assertEquals($filter, 'kses <a href="kses\\\\kses">');
    }

    public function testCorrectTag11(): void
    {
        $filter = $this->xss
            ->addAllowedTag('a', [ 'href' => [ 'maxlen' => 6 ] ])
            ->filter('kses <a href="xxxxxx">');

        $this->assertEquals($filter, 'kses <a href="xxxxxx">');
    }

    public function testCorrectTag12(): void
    {
        $filter = $this->xss
            ->addAllowedTag('a', [ 'href' => [ 'maxlen' => 6 ] ])
            ->filter('kses <a href="xxxxxxx">');

        $this->assertEquals($filter, 'kses <a>');
    }

    public function testCorrectTag13(): void
    {
        $filter = $this->xss
            ->addAllowedTag('a', [ 'href' => [ 'maxval' => 686 ] ])
            ->filter('kses <a href="687">');

        $this->assertEquals($filter, 'kses <a>');
    }

    public function testCorrectTag14(): void
    {
        $filter = $this->xss
            ->addAllowedTag('a', [ 'href' => [ 'maxlen' => 6 ] ])
            ->filter('kses <a href="xx"   /  >');

        $this->assertEquals($filter, 'kses <a href="xx" />');
    }

    public function testCorrectTag15(): void
    {
        $filter = $this->xss
            ->filter('kses <a href="JAVA java scrIpt : SCRIPT  :  alert(57)">');

        $this->assertEquals($filter, 'kses <a href="alert(57)">');
    }

    public function testCorrectTag16(): void
    {
        $filter = $this->xss
            ->filter('kses <a href="' . chr(173) . '">');

        $this->assertEquals($filter, '');

        $filter2 = $this->xss
            ->filter('kses <a href="htt&#32; &#173;&#Xad;P://ulf">');

        $this->assertEquals($filter2, 'kses <a href="http://ulf">');
    }

    public function testCorrectTag17(): void
    {
        $filter = $this->xss
            ->filter('kses <a href="/start.php"> kses <a href="start.php">');

        $this->assertEquals($filter, 'kses <a href="/start.php"> kses <a href="start.php">');
    }

    public function testVoid(): void
    {
        $filter = $this->xss
            ->filter('');

        $this->assertEquals($filter, '');
    }

    public function testComment(): void
    {
        $filter = $this->xss
            ->addAllowedTag('!--')
            ->filter('kses <!-- comment -->');

        $this->assertEquals($filter, 'kses <!-- comment -->');
    }
}
