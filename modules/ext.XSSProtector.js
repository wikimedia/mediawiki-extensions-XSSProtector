$( () => {
	// Unfortunately script-src-elem 'unsafe-inline' controls both
	// <script>foo</script> and <a href="javascript:...
	// We want to disable the latter as it is difficult to regex for
	// but we want to keep the former to be minimally invasive
	// We only need the former during initial loading, so we add
	// a meta tag after DOMContentLoaded to disable after this point.
	// Thus an attacker would have to trick the user into clicking the
	// javascript link really fast.
	var meta = document.createElement( 'meta' );
	meta.httpEquiv = 'Content-Security-Policy';
	meta.content = 'script-src-elem *';
	document.head.appendChild( meta );
} );
