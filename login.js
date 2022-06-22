//给登录界面的action加上时间戳

var _path = "/jwglxt";
var _systemPath = "/jwglxt";
var _stylePath = "/zftal-ui-v5-1.0.2";

var b64map = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
var b64pad = "=";

// Depends on jsbn.js and rng.js

// Version 1.1: support utf-8 encoding in pkcs1pad2

// convert a (hex) string to a bignum object
function parseBigInt(str, r) {
	return new BigInteger(str, r);
}

function linebrk(s, n) {
	var ret = "";
	var i = 0;
	while (i + n < s.length) {
		ret += s.substring(i, i + n) + "\n";
		i += n;
	}
	return ret + s.substring(i, s.length);
}

function byte2Hex(b) {
	if (b < 0x10)
		return "0" + b.toString(16);
	else
		return b.toString(16);
}

// PKCS#1 (type 2, random) pad input string s to n bytes, and return a bigint
function pkcs1pad2(s, n) {
	if (n < s.length + 11) { // TODO: fix for utf-8
		alert("Message too long for RSA");
		return null;
	}
	var ba = new Array();
	var i = s.length - 1;
	while (i >= 0 && n > 0) {
		var c = s.charCodeAt(i--);
		if (c < 128) { // encode using utf-8
			ba[--n] = c;
		}
		else if ((c > 127) && (c < 2048)) {
			ba[--n] = (c & 63) | 128;
			ba[--n] = (c >> 6) | 192;
		}
		else {
			ba[--n] = (c & 63) | 128;
			ba[--n] = ((c >> 6) & 63) | 128;
			ba[--n] = (c >> 12) | 224;
		}
	}
	ba[--n] = 0;
	var rng = new SecureRandom();
	var x = new Array();
	while (n > 2) { // random non-zero pad
		x[0] = 0;
		while (x[0] == 0) rng.nextBytes(x);
		ba[--n] = x[0];
	}
	ba[--n] = 2;
	ba[--n] = 0;
	return new BigInteger(ba);
}

// "empty" RSA key constructor
function RSAKey() {
	this.n = null;
	this.e = 0;
	this.d = null;
	this.p = null;
	this.q = null;
	this.dmp1 = null;
	this.dmq1 = null;
	this.coeff = null;
}

// Set the public key fields N and e from hex strings
function RSASetPublic(N, E) {
	if (N != null && E != null && N.length > 0 && E.length > 0) {
		this.n = parseBigInt(N, 16);
		this.e = parseInt(E, 16);
	}
	else
		alert("Invalid RSA public key");
}

// Perform raw public operation on "x": return x^e (mod n)
function RSADoPublic(x) {
	return x.modPowInt(this.e, this.n);
}

// Return the PKCS#1 RSA encryption of "text" as an even-length hex string
function RSAEncrypt(text) {
	var m = pkcs1pad2(text, (this.n.bitLength() + 7) >> 3);
	if (m == null) return null;
	var c = this.doPublic(m);
	if (c == null) return null;
	var h = c.toString(16);
	if ((h.length & 1) == 0) return h; else return "0" + h;
}

// Return the PKCS#1 RSA encryption of "text" as a Base64-encoded string
//function RSAEncryptB64(text) {
//  var h = this.encrypt(text);
//  if(h) return hex2b64(h); else return null;
//}

// protected
RSAKey.prototype.doPublic = RSADoPublic;

// public
RSAKey.prototype.setPublic = RSASetPublic;
RSAKey.prototype.encrypt = RSAEncrypt;
//RSAKey.prototype.encrypt_b64 = RSAEncryptB64;



function hex2b64(h) {
	var i;
	var c;
	var ret = "";
	for (i = 0; i + 3 <= h.length; i += 3) {
		c = parseInt(h.substring(i, i + 3), 16);
		ret += b64map.charAt(c >> 6) + b64map.charAt(c & 63);
	}
	if (i + 1 == h.length) {
		c = parseInt(h.substring(i, i + 1), 16);
		ret += b64map.charAt(c << 2);
	}
	else if (i + 2 == h.length) {
		c = parseInt(h.substring(i, i + 2), 16);
		ret += b64map.charAt(c >> 2) + b64map.charAt((c & 3) << 4);
	}
	while ((ret.length & 3) > 0) ret += b64pad;
	return ret;
}

// convert a base64 string to hex
function b64tohex(s) {
	var ret = ""
	var i;
	var k = 0; // b64 state, 0-3
	var slop;
	for (i = 0; i < s.length; ++i) {
		if (s.charAt(i) == b64pad) break;
		v = b64map.indexOf(s.charAt(i));
		if (v < 0) continue;
		if (k == 0) {
			ret += int2char(v >> 2);
			slop = v & 3;
			k = 1;
		}
		else if (k == 1) {
			ret += int2char((slop << 2) | (v >> 4));
			slop = v & 0xf;
			k = 2;
		}
		else if (k == 2) {
			ret += int2char(slop);
			ret += int2char(v >> 2);
			slop = v & 3;
			k = 3;
		}
		else {
			ret += int2char((slop << 2) | (v >> 4));
			ret += int2char(v & 0xf);
			k = 0;
		}
	}
	if (k == 1)
		ret += int2char(slop << 2);
	return ret;
}

// convert a base64 string to a byte/number array
function b64toBA(s) {
	//piggyback on b64tohex for now, optimize later
	var h = b64tohex(s);
	var i;
	var a = new Array();
	for (i = 0; 2 * i < h.length; ++i) {
		a[i] = parseInt(h.substring(2 * i, 2 * i + 2), 16);
	}
	return a;
}

var modulus, exponent;

$.getJSON(_path + "/xtgl/login_getPublicKey.html?time=" + new Date().getTime(), function (data) {
	modulus = data["modulus"];
	exponent = data["exponent"];
});
var rsaKey = new RSAKey();
rsaKey.setPublic(b64tohex(modulus), b64tohex(exponent));
var enPassword = hex2b64(rsaKey.encrypt("111111"));
alert(enPassword);