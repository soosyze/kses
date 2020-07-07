<?php

namespace Kses\Tests;

use Kses\Kses;
use Kses\KsesAllowedList;

class KsesTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @var Kses
     */
    protected $kses;

    protected function setUp()
    {
        $this->kses = new Kses(KsesAllowedList::getTagsAdmin());
    }

    public function testCorrectTag()
    {
        $html   = 'kses \'kses\' /kses "kses" kses \\kses\\';
        $filter = $this->kses->filter($html);

        $this->assertEquals($html, $filter);
    }

    public function testCorrectTag2()
    {
        $filter = (new Kses)->filter('kses<br>');

        $this->assertEquals($filter, 'kses<br>');
    }

    public function testCorrectTag3()
    {
        $filter = $this->kses
            ->addAllowedTag('br')
            ->filter('kses <BR >');

        $this->assertEquals($filter, 'kses <BR>');
    }

    public function testCorrectTag4()
    {
        $filter = $this->kses
            ->addAllowedTag('br')
            ->filter('kses > 5 <br>');

        $this->assertEquals($filter, 'kses &gt; 5 <br>');
    }

    public function testCorrectTag5()
    {
        $filter = $this->kses
            ->addAllowedTag('br')
            ->filter('kses < br');

        $this->assertEquals($filter, 'kses &lt; br');
    }

    public function testCorrectTag6()
    {
        $filter = $this->kses
            ->setAllowedTags([
                'br' => [],
                'a'  => []
            ])
            ->filter('kses <a href=5>');

        $this->assertEquals($filter, 'kses <a>');
    }

    public function testCorrectTag7()
    {
        $filter = $this->kses
            ->filter('kses <a href=5>');

        $this->assertEquals($filter, 'kses <a href="5">');
    }

    public function testCorrectTag8()
    {
        $filter = $this->kses
            ->filter('kses <a href>');

        $this->assertEquals($filter, 'kses <a href>');
    }

    public function testCorrectTag9()
    {
        $filter = $this->kses
            ->filter('kses <a href href=5 href=\'5\' href="5" dummy>');

        $this->assertEquals($filter, 'kses <a href href="5" href=\'5\' href="5">');
    }

    public function testCorrectTag10()
    {
        $filter = $this->kses
            ->filter('kses <a href="kses\\\\kses">');

        $this->assertEquals($filter, 'kses <a href="kses\\\\kses">');
    }

    public function testCorrectTag11()
    {
        $filter = $this->kses
            ->addAllowedTag('a', [ 'href' => [ 'maxlen' => 6 ] ])
            ->filter('kses <a href="xxxxxx">');

        $this->assertEquals($filter, 'kses <a href="xxxxxx">');
    }

    public function testCorrectTag12()
    {
        $filter = $this->kses
            ->addAllowedTag('a', [ 'href' => [ 'maxlen' => 6 ] ])
            ->filter('kses <a href="xxxxxxx">');

        $this->assertEquals($filter, 'kses <a>');
    }

    public function testCorrectTag13()
    {
        $filter = $this->kses
            ->addAllowedTag('a', [ 'href' => [ 'maxval' => 686 ] ])
            ->filter('kses <a href="687">');

        $this->assertEquals($filter, 'kses <a>');
    }

    public function testCorrectTag14()
    {
        $filter = $this->kses
            ->addAllowedTag('a', [ 'href' => [ 'maxlen' => 6 ] ])
            ->filter('kses <a href="xx"   /  >');

        $this->assertEquals($filter, 'kses <a href="xx" />');
    }

    public function testCorrectTag15()
    {
        $filter = $this->kses
            ->filter('kses <a href="JAVA java scrIpt : SCRIPT  :  alert(57)">');

        $this->assertEquals($filter, 'kses <a href="alert(57)">');
    }

    public function testCorrectTag16()
    {
        $filter = $this->kses
            ->filter('kses <a href="' . chr(173) . '">');

        $this->assertEquals($filter, '');

        $filter2 = $this->kses
            ->filter('kses <a href="htt&#32; &#173;&#Xad;P://ulf">');

        $this->assertEquals($filter2, 'kses <a href="http://ulf">');
    }

    public function testCorrectTag17()
    {
        $filter = $this->kses
            ->filter('kses <a href="/start.php"> kses <a href="start.php">');

        $this->assertEquals($filter, 'kses <a href="/start.php"> kses <a href="start.php">');
    }
    
    public function testVoid()
    {
        $filter = $this->kses
            ->filter('');

        $this->assertEquals($filter, '');
    }
    
    public function testComment()
    {
        $filter = $this->kses
            ->addAllowedTag('!--')
            ->filter('kses <!-- comment -->');

        $this->assertEquals($filter, 'kses <!-- comment -->');
    }
}
