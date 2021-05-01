<?php

declare(strict_types=1);

namespace Kses;

class KsesAllowedList
{
    /**
     * @return array
     */
    public static function getProtocols(): array
    {
        return [
            'ftp', 'http', 'https', 'irc', 'mailto', 'news', 'nntp', 'rtsp', 'sftp',
            'ssh', 'tel', 'telnet', 'webcal'
        ];
    }

    /**
     * List of tags authorized for a user profile (standard tag for forums).
     *
     * @return array
     */
    public static function getTags(): array
    {
        return [
            'a'          => [
                'class'    => 1,
                'download' => [
                    'valueless' => 'y',
                ],
                'href'     => 1,
                'rel'      => 1,
                'rev'      => 1,
                'name'     => 1,
                'target'   => 1
            ],
            'abbr'       => [
                'class' => 1,
                'lang'  => 1,
                'title' => 1
            ],
            'b'          => [ 'class' => 1 ],
            'blockquote' => [
                'cite'     => 1,
                'class'    => 1,
                'lang'     => 1,
                'xml:lang' => 1
            ],
            'br'         => [],
            'cite'       => [
                'class' => 1,
                'dir'   => 1,
                'lang'  => 1
            ],
            'code'       => [ 'class' => 1 ],
            'dd'         => [ 'class' => 1 ],
            'div'        => [
                'align'    => 1,
                'class'    => 1,
                'dir'      => 1,
                'lang'     => 1,
                'style'    => [
                    'content' => [
                        'text-align: center;',
                        'text-align: left;',
                        'text-align: justify;',
                        'text-align: right;'
                    ]
                ],
                'xml:lang' => 1
            ],
            'dl'         => [ 'class' => 1 ],
            'dt'         => [ 'class' => 1 ],
            'em'         => [ 'class' => 1 ],
            'i'          => [ 'aria-hidden' => 1, 'class' => 1 ],
            'img'        => [
                'alt'      => 1,
                'align'    => 1,
                'class'    => 1,
                'border'   => 1,
                'height'   => 1,
                'hspace'   => 1,
                'longdesc' => 1,
                'vspace'   => 1,
                'src'      => 1,
                'usemap'   => 1,
                'width'    => 1
            ],
            'kbd'        => [ 'class' => 1 ],
            'li'         => [ 'class' => 1 ],
            'mark'       => [ 'class' => 1 ],
            'ol'         => [ 'class' => 1 ],
            'p'          => [
                'align'    => 1,
                'class'    => 1,
                'dir'      => 1,
                'lang'     => 1,
                'style'    => [
                    'content' => [
                        'text-align: center;',
                        'text-align: left;',
                        'text-align: justify;',
                        'text-align: right;'
                    ]
                ],
                'xml:lang' => 1
            ],
            'pre'        => [
                'class' => 1,
                'width' => 1
            ],
            'small'      => [ 'class' => 1 ],
            'strong'     => [ 'class' => 1 ],
            'sub'        => [ 'class' => 1 ],
            'sup'        => [ 'class' => 1 ],
            'u'          => [ 'class' => 1 ],
            'ul'         => [ 'class' => 1 ],
            'var'        => [ 'class' => 1 ]
        ];
    }

    /**
     * List of authorized tags for an administrator profile.
     *
     * @return array
     */
    public static function getTagsAdmin(): array
    {
        return self::getTags() + [
            'acronym'    => [
                'class' => 1,
                'lang'  => 1,
                'title' => 1
            ],
            'address'    => [
                'class' => 1,
                'lang'  => 1,
                'title' => 1
            ],
            'area'       => [
                'alt'    => 1,
                'class'  => 1,
                'coords' => 1,
                'href'   => 1,
                'nohref' => 1,
                'shape'  => 1,
                'target' => 1
            ],
            'article'    => [
                'align'    => 1,
                'class'    => 1,
                'dir'      => 1,
                'lang'     => 1,
                'xml:lang' => 1
            ],
            'aside'      => [
                'align'    => 1,
                'class'    => 1,
                'dir'      => 1,
                'lang'     => 1,
                'xml:lang' => 1
            ],
            'audio'      => [
                'autoplay' => 1,
                'class'    => 1,
                'controls' => 1,
                'loop'     => 1,
                'muted'    => 1,
                'preload'  => 1,
                'src'      => 1
            ],
            'bdi'        => [ 'class' => 1 ],
            'bdo'        => [ 'class' => 1, 'dir' => 1 ],
            'big'        => [ 'class' => 1 ],
            'button'     => [
                'class'    => 1,
                'disabled' => 1,
                'name'     => 1,
                'type'     => 1,
                'value'    => 1
            ],
            'caption'    => [ 'align' => 1 ],
            'col'        => [
                'align'   => 1,
                'char'    => 1,
                'charoff' => 1,
                'class'   => 1,
                'span'    => 1,
                'dir'     => 1,
                'valign'  => 1,
                'width'   => 1
            ],
            'colgroup'   => [
                'align'   => 1,
                'char'    => 1,
                'charoff' => 1,
                'class'   => 1,
                'span'    => 1,
                'valign'  => 1,
                'width'   => 1
            ],
            'del'        => [ 'class' => 1, 'datetime' => 1 ],
            'details'    => [
                'align'    => 1,
                'class'    => 1,
                'dir'      => 1,
                'lang'     => 1,
                'open'     => 1,
                'xml:lang' => 1
            ],
            'dfn'        => [ 'class' => 1 ],
            'fieldset'   => [ 'class' => 1 ],
            'figcaption' => [
                'align'    => 1,
                'class'    => 1,
                'dir'      => 1,
                'lang'     => 1,
                'xml:lang' => 1
            ],
            'figure'     => [
                'align'    => 1,
                'class'    => 1,
                'dir'      => 1,
                'lang'     => 1,
                'xml:lang' => 1
            ],
            'font'       => [
                'color' => 1,
                'class' => 1,
                'face'  => 1,
                'size'  => 1
            ],
            'footer'     => [
                'align'    => 1,
                'class'    => 1,
                'dir'      => 1,
                'lang'     => 1,
                'xml:lang' => 1
            ],
            'h1'         => [
                'align' => 1,
                'class' => 1,
                'style' => [
                    'content' => [
                        'text-align: center;',
                        'text-align: left;',
                        'text-align: justify;',
                        'text-align: right;'
                    ]
                ],
            ],
            'h2'         => [
                'align' => 1,
                'class' => 1,
                'style' => [
                    'content' => [
                        'text-align: center;',
                        'text-align: left;',
                        'text-align: justify;',
                        'text-align: right;'
                    ]
                ],
            ],
            'h3'         => [
                'align' => 1,
                'class' => 1,
                'style' => [
                    'content' => [
                        'text-align: center;',
                        'text-align: left;',
                        'text-align: justify;',
                        'text-align: right;'
                    ]
                ],
            ],
            'h4'         => [
                'align' => 1,
                'class' => 1,
                'style' => [
                    'content' => [
                        'text-align: center;',
                        'text-align: left;',
                        'text-align: justify;',
                        'text-align: right;'
                    ]
                ],
            ],
            'h5'         => [
                'align' => 1,
                'class' => 1,
                'style' => [
                    'content' => [
                        'text-align: center;',
                        'text-align: left;',
                        'text-align: justify;',
                        'text-align: right;'
                    ]
                ],
            ],
            'h6'         => [
                'align' => 1,
                'class' => 1,
                'style' => [
                    'content' => [
                        'text-align: center;',
                        'text-align: left;',
                        'text-align: justify;',
                        'text-align: right;'
                    ]
                ],
            ],
            'header'     => [
                'align'    => 1,
                'class'    => 1,
                'dir'      => 1,
                'lang'     => 1,
                'xml:lang' => 1
            ],
            'hgroup'     => [
                'align'    => 1,
                'class'    => 1,
                'dir'      => 1,
                'lang'     => 1,
                'xml:lang' => 1
            ],
            'hr'         => [
                'align'   => 1,
                'class'   => 1,
                'noshade' => 1,
                'size'    => 1,
                'width'   => 1
            ],
            'iframe'     => [
                'allowfullscreen' => 1,
                'frameborder'     => 1,
                'height'          => 1,
                'sandbox'         => 1,
                'scrolling'       => 1,
                'src'             => 1,
                'marginheight'    => 1,
                'marginwidth'     => 1,
                'title'           => 1,
                'width'           => 1
            ],
            'ins'        => [
                'datetime' => 1,
                'cite'     => 1,
                'class'    => 1
            ],
            'label'      => [ 'class' => 1, 'for' => 1 ],
            'legend'     => [ 'align' => 1, 'class' => 1 ],
            'map'        => [ 'class' => 1, 'name' => 1 ],
            'menu'       => [ 'class' => 1, 'type' => 1 ],
            'meter'      => [ 'class' => 1 ],
            'nav'        => [
                'align'    => 1,
                'class'    => 1,
                'dir'      => 1,
                'lang'     => 1,
                'xml:lang' => 1
            ],
            'output'     => [ 'class' => 1 ],
            'progress'   => [ 'class' => 1 ],
            'q'          => [ 'cite' => 1, 'class' => 1 ],
            'rp'         => [ 'class' => 1 ],
            'rt'         => [ 'class' => 1 ],
            'ruby'       => [ 'class' => 1 ],
            's'          => [ 'class' => 1 ],
            'samp'       => [ 'class' => 1 ],
            'section'    => [
                'align'    => 1,
                'class'    => 1,
                'dir'      => 1,
                'lang'     => 1,
                'xml:lang' => 1
            ],
            'span'       => [
                'align'    => 1,
                'class'    => 1,
                'dir'      => 1,
                'lang'     => 1,
                'xml:lang' => 1
            ],
            'strike'     => [ 'class' => 1 ],
            'summary'    => [
                'align'    => 1,
                'class'    => 1,
                'dir'      => 1,
                'lang'     => 1,
                'xml:lang' => 1
            ],
            'table'      => [
                'align'       => 1,
                'bgcolor'     => 1,
                'border'      => 1,
                'cellpadding' => 1,
                'cellspacing' => 1,
                'class'       => 1,
                'dir'         => 1,
                'rules'       => 1,
                'summary'     => 1,
                'width'       => 1
            ],
            'tbody'      => [
                'align'   => 1,
                'char'    => 1,
                'charoff' => 1,
                'class'   => 1,
                'valign'  => 1
            ],
            'td'         => [
                'abbr'    => 1,
                'align'   => 1,
                'axis'    => 1,
                'bgcolor' => 1,
                'char'    => 1,
                'charoff' => 1,
                'class'   => 1,
                'colspan' => 1,
                'dir'     => 1,
                'headers' => 1,
                'height'  => 1,
                'nowrap'  => 1,
                'rowspan' => 1,
                'scope'   => 1,
                'valign'  => 1,
                'width'   => 1
            ],
            'tfoot'      => [
                'align'   => 1,
                'char'    => 1,
                'charoff' => 1,
                'class'   => 1,
                'valign'  => 1
            ],
            'th'         => [
                'abbr'    => 1,
                'align'   => 1,
                'axis'    => 1,
                'bgcolor' => 1,
                'char'    => 1,
                'charoff' => 1,
                'class'   => 1,
                'colspan' => 1,
                'headers' => 1,
                'height'  => 1,
                'nowrap'  => 1,
                'rowspan' => 1,
                'scope'   => 1,
                'valign'  => 1,
                'width'   => 1
            ],
            'thead'      => [
                'align'   => 1,
                'char'    => 1,
                'charoff' => 1,
                'class'   => 1,
                'valign'  => 1
            ],
            'title'      => [ 'class' => 1 ],
            'tr'         => [
                'align'   => 1,
                'bgcolor' => 1,
                'char'    => 1,
                'charoff' => 1,
                'class'   => 1,
                'valign'  => 1
            ],
            'track'      => [
                'class'   => 1,
                'default' => 1,
                'kind'    => 1,
                'label'   => 1,
                'src'     => 1,
                'srclang' => 1
            ],
            'tt'         => [ 'class' => 1 ],
            'video'      => [
                'autoplay' => 1,
                'class'    => 1,
                'controls' => 1,
                'height'   => 1,
                'loop'     => 1,
                'muted'    => 1,
                'poster'   => 1,
                'preload'  => 1,
                'src'      => 1,
                'width'    => 1
            ],
            'wbr'        => [ 'class' => 1 ]
        ];
    }
}
