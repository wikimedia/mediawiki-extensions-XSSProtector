<?php
namespace MediaWiki\Extension\XSSProtector;

use ExtensionRegistry;
use MediaWiki\MediaWikiServices;
use RuntimeException;
use MobileContext;
use Message;

class Hooks {

	/**
	 * @note Not using onBeforePageDisplay because it does not catch ?action=render.
	 * @inheritDoc
	 */
	public static function onAfterFinalPageOutput( $out ) {
		$resp = $out->getRequest()->response();
		// We also add a meta tag "script-src-elem *" to block
		// unsafe-inline after page load.
		$policy = "script-src-attr 'none';";
		if ( $wgXSSProtectorScriptless ) {
			$policy .= "base-uri 'none';";
			$policy .= "object-src 'none';";
			$policy .= "form-action 'self';";
		} else {
			$policy .= "base-uri 'self';";
		}
		// 2nd argument false for compat with builtin MW CSP.
		$resp->header( 'Content-Security-Policy: ' . $policy, false );
	}

	/**
	 * Not sure if this is the best option. The other main option is:
	 * onParserOutputPostCacheTransform.
	 * This will catch main article contents but will not catch
	 * things like $wgOut->addHtml(). It is run on ?action=view and ?action=render.
	 * @inheritDoc
	 */
	public static function onOutputPageBeforeHTML( $out, &$text ) {
		$text = self::doReplacementsHtml( $text );
	}

	/**
	 * This is meant to catch SpecialPage ->addHTML().
	 * This overlaps with onOutputPageBeforeHTML except it does
	 * not get called for ?action=render while the other one does.
	 * @inheritDoc
	 */
	public static function onBeforePageDisplay( $out, $skin ) {
		// Make sure we do <indicator>
		// An alternative might be to hook into ParserAfterTidy
		$indicators = array_map( [ __CLASS__, 'doReplacementsHtml' ], $out->getIndicators() );
		$out->setIndicators( $indicators );

		$out->addModules( 'ext.XSSProtector.init' );
		if ( ExtensionRegistry::getInstance()->isLoaded( 'MobileFrontend' ) ) {
			if ( MobileContext::singleton()
				->shouldDisplayMobileView()
			) {
				// Mobile frontend inserts inline <script> tags
				// which this hook breaks but the other one doesn't touch.
				return;
			}
		}
		if ( $wgXSSProtectorLaxSpecialPage ) {
			return;
		}
		$text = $out->getHTML();
		// Use the more lax approach for ->addHTML
		$newText = self::doReplacementsHtml( $text, false );
		$out->clearHTML();
		$out->addHTML( $newText );
	}

	/**
	 * Custom hook for wfMessage plain and text formats
	 *
	 * @param string &$text
	 */
	public static function onXSSProtectorMsgText( &$text ) {
		$text = self::doReplacementsText( $text );
	}

	/**
	 * Custom hook for wfMessage plain and text formats
	 *
	 * @param string &$text
	 */
	public static function onXSSProtectorMsgHtml( &$text ) {
		$text = self::doReplacementsHtml( $text );
	}

	/**
	 * Do replacements if the text is meant to be HTML
	 *
	 * @param string $text Text to escape
	 * @param bool $doAll Do the scriptless stuff too
	 * @return string
	 */
	private static function doReplacementsHTML( $text, $doAll = true ) {
		global $wgXSSProtectorScriptless;
		$text = preg_replace( '/<(script)/i', '&lt;$1', $text );
		// This is the sketchiest part of the whole thing.
		// Designed to hopefully have (rare) false positives but not false negatives.
		// We use a meta tag to block javascript: uris after DOMContentLoaded fires,
		// so even if this regex fails, attackers have only a limited opportunity to
		// convince someone to click on the link.
		// We use \u{2060} to keep it a valid attribute. Originally we replaced
		// the equal sign with &#61; however that allowed escaping the attribute.
		$text = preg_replace(
			'@([ \t\f\n\r\0/]href[\0\t\f\n\r ]*+)=(?![\0\t\f\n\r ]*+[\'"]?(?:[a-ik-z0-9/]|[^:\'"/]++[\'"/]))@i',
			"$1\u{2060}=",
			$text
		);
		if ( $doAll && $wgXSSProtectorScriptless ) {
			// Contemplated adding <form> here, but going to rely on CSP
			// due to risk of false positive, and not really being sufficient
			// unless formaction attribute is also banned. The other big risk
			// is <style>, both unclosed but also various text extraction methods.
			// <style> is probably biggest scriptless risk, but its not really viable
			// to do anything about it without breaking TemplateStyles. <base> is
			// included here for target attribute,
			// with href protection provided by CSP.
			$text = preg_replace( '/<(meta|base)/i', '&lt;$1', $text );
		}
		return $text;
	}

	/**
	 * Make these html tags not work in places where text is not HTML
	 *
	 * We use U+2060 WORD JOINER, which is an invisible unicode character that
	 * does nothing, but per html5 spec, should break the HTML tags
	 *
	 * Potentially we could simplify things by using this in both cases.
	 * @param string $text
	 * @return string
	 */
	private static function doReplacementsText( string $text ) {
		global $wgXSSProtectorScriptless;
		$text = preg_replace( '/<(script)/i', "<\u{2060}" . '$1', $text );
		// This is the sketchiest part of the whole thing.
		// Designed to hopefully have (rare) false positives but not false negatives.
		$text = preg_replace(
			'@([ \t\f\n\r\0/]href[\0\t\f\n\r ]*+)=(?![\0\t\f\n\r ]*+[\'"]?(?:[a-ik-z0-9/]|[^:\'"/]++[\'"/]))@i',
			'$1' . "\u{2060}=",
			$text
		);
		if ( $wgXSSProtectorScriptless ) {
			$text = preg_replace( '/<(meta|base)/i', "<\u{2060}" . '$1', $text );
		}
		return $text;
	}

	/**
	 * Registration call back
	 *
	 * Do evil stuff to override wfMessage
	 */
	public static function setup() {
		global $wgXSSProtectorReplaceMessage;
		// EVIL hack to replace the message class.
		if ( $wgXSSProtectorReplaceMessage ) {
			if ( class_exists( Message::class, false ) ) {
				// Another extension caused this to load early.
				// You can disable this part with $wgXSSProtectorReplaceMessage but
				// it significantly reduces the protection.
				throw new RuntimeException(
					"Message class loaded too early." .
					"Set $wgXSSProtectorReplaceMessage = false; to disable"
				);
			} else {
				require_once __DIR__ . '/Message.php';
			}
		}
	}

}
