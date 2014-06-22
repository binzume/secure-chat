/*
  SSH pub key util.
  Copyright (c) 2014 Kousuke Kawahira
  License: MIT License.
*/

function int2hex(n) {
 	return ("0000000" + n.toString(16)).substr(-8);
}
function stohex(s) {
	var len = s.length;
	var ret = "";
	for (var i=0; i<len; i++) {
		var c = s.charCodeAt(i).toString(16);
		if (c.length < 2) c = "0" + c;
		ret += c;
	}
	return ret;
}
function hex2b64(h) {
	var len = h.length / 2;
	var buf = new Uint8Array(len);
	for (var i=0; i<len; i++) {
		buf[i] = parseInt(h.substr(i*2,2),16);
	}
	return btoa(String.fromCharCode.apply(null, buf));
}
function sshkey(key) {
	var e = "0"+key.e.toString(16);
	var n = "0"+key.n.toString(16);
	var e = e.substr(e.length%2);
	var n = n.substr(n.length%2);
	var hex = int2hex(7) + stohex("ssh-rsa") + int2hex(e.length/2) + e + int2hex(n.length/2) + n;
	return "ssh-rsa " + hex2b64(hex);
}

function b64tohex(b) {
    var buf = atob(b);
    var len = buf.length;
    var ret = "";
    for (var i=0; i<len; i++) {
    var c = buf.charCodeAt(i).toString(16);
        if (c.length < 2) c = "0" + c;
        ret += c;
    }
    return ret;
}

