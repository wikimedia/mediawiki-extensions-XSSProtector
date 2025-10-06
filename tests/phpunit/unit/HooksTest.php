<?php
namespace MediaWiki\Extension\XSSProtector\Tests;

use MediaWiki\Config\HashConfig;
use MediaWiki\Extension\XSSProtector\Hooks;
use MediaWiki\Message\Message;
use MediaWiki\Output\OutputPage;
use MediaWikiUnitTestCase;

/**
 * @covers \MediaWiki\Extension\XSSProtector\Hooks
 */
class HooksTest extends MediaWikiUnitTestCase {

	private Hooks $hooks;

	protected function setUp(): void {
		$config = new HashConfig( [
			'XSSProtectorScriptless' => true
		] );
		$this->hooks = new Hooks( $config );
	}

	/**
	 * @dataProvider provideOnMessagePostProcessText
	 */
	public function testOnMessagePostProcessText( $input, $expected ) {
		// modify in place.
		$this->hooks->onMessagePostProcessText( $input, MESSAGE::FORMAT_TEXT, 'foo' );
		$this->assertEquals( $expected, $input );
	}

	public function provideOnMessagePostProcessText() {
		yield [ '<foo> bar</foo>', '<foo> bar</foo>' ];
		yield [ '<script>alert(1)</script>', "<\u{2060}script>alert(1)</script>" ];
		yield [ '<script attrib>alert(1)</script>', "<\u{2060}script attrib>alert(1)</script>" ];
		yield [ '<a href="javascript:alert(1)">foo</a>', "<a href\u{2060}=\"javascript:alert(1)\">foo</a>" ];
		yield [ '<div data-href="dsf">dafs</div>', '<div data-href="dsf">dafs</div>' ];
	}

	/**
	 * @dataProvider provideOnMessagePostProcessHtml
	 */
	public function testOnMessagePostProcessHtml( $input, $expected ) {
		// modify in place.
		$this->hooks->onMessagePostProcessHtml( $input, MESSAGE::FORMAT_PARSE, 'foo' );
		$this->assertEquals( $expected, $input );
	}

	public function provideOnMessagePostProcessHtml() {
		yield [ '<foo> bar</foo>', '<foo> bar</foo>' ];
		yield [ '<script>alert(1)</script>', "&lt;script>alert(1)</script>" ];
		yield [ '<script attrib>alert(1)</script>', "&lt;script attrib>alert(1)</script>" ];
		yield [ '<a href="javascript:alert(1)">foo</a>', "<a href\u{2060}=\"javascript:alert(1)\">foo</a>" ];
		yield [ '<div data-href="dsf">dafs</div>', '<div data-href="dsf">dafs</div>' ];
	}

	/**
	 * @dataProvider provideOnMessagePostProcessHtml
	 */
	public function testOnOutputPageBeforeHTML( $input, $expected ) {
		$output = $this->createMock( OutputPage::class );
		$this->hooks->onOutputPageBeforeHTML( $output, $input );
		$this->assertEquals( $expected, $input );
	}

}
