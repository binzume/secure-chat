/*
  RSASSA-PSS library
  Copyright (c) 2014 Kousuke Kawahira
  License: MIT License.
*/

function hex2(i) {
    return (i < 16 ? "0":"") + i.toString(16);
}

function hex_xor(a, b) {
	var len = a.length/2;
	var ret = "";
	for (var i = 0; i < len; i++) {
		ret += hex2(parseInt(a.substr(i*2,2),16) ^ parseInt(b.substr(i*2,2),16));
	}
	return ret;
}

function hex2bin(h) {
  var len = h.length / 2;
  var buf = new Uint8Array(len);
  for (var i=0; i<len; i++) {
    buf[i] = parseInt(h.substr(i*2,2),16);
  }
  return String.fromCharCode.apply(null, buf);
}

function hash(hex) {
	return CybozuLabs.SHA1.calc(hex2bin(hex));
}

// RFC 3447
function pss_encode(key, msg) {
	var sLen = 0; // FIXME
	var hLen = 160 / 8;
	var emBits = key.n.bitLength() - 1;
	var emLen = Math.ceil(emBits / 8);
	
	// 1 skip

	// 2
	var mHash = CybozuLabs.SHA1.calc(msg);

	// 3
	if (emLen < hLen + sLen + 2) {
		return null; // encoding error
	}

	// 4
	var salt = ""; // todo: random

	// 5
	var M2 = "0000000000000000" + mHash + salt;

	// 6
	var H = hash(M2);

	// 7
	var PS = "";
	for (var i = 0; i < emLen - sLen - hLen - 2; i++) {
		PS += "00";
	}

	// 8
	var DB = PS + "01" + salt;

	// 9 MGF
	var mgfSeed = H;
	var maskLen = DB.length / 2;
	var T = "";
	for (var counter = 0; counter < Math.ceil(maskLen / hLen); counter++) {
		T = T + hash(mgfSeed + int2hex(counter));
	}
	// 10
	var maskedDB = hex_xor(DB, T);

	// 11
	var msb = parseInt(maskedDB.substr(0,2), 16);
	msb &= (0xff >> (8*emLen - emBits));
	maskedDB = hex2(msb) + maskedDB.substr(2);

	// 12
	var EM = maskedDB + H + "bc";

	return EM;
}

function sign(key, msg) {
	var em = pss_encode(key, msg);
	var b = key.n.clone();
	b.fromRadix(em,16);
	return key.doPrivate(b).toString(16);
}

function verify(key, sig, msg) {
	var sLen = 0; // FIXME
	var hLen = 160 / 8;
	var emBits = key.n.bitLength() - 1;
	var emLen = Math.ceil(emBits / 8);

	var mHash = CybozuLabs.SHA1.calc(msg);

	var emb = key.n.clone();
	emb.fromRadix(sig,16);
	var em = key.doPublic(emb).toString(16);
	
	while (em.length < emLen*2) {
		em = "0" + em;
	}
	
	if (em.substr(-2) != "bc") {
		console.log("err != bc");
		return false;
	}
	
    var maskedDB = em.substr(0, (emLen - hLen - 1) * 2);
    var H = em.substr(maskedDB.length, hLen * 2);


	// 9 MGF
	var mgfSeed = H;
	var maskLen = maskedDB.length / 2;
	var T = "";
	for (var counter = 0; counter < Math.ceil(maskLen / hLen); counter++) {
		T = T + hash(mgfSeed + int2hex(counter));
	}
	// 10
	var DB = hex_xor(maskedDB, T);

    // 11
	var msb = parseInt(DB.substr(0,2), 16);
	msb &= (0xff >> (8*emLen - emBits));
	DB = hex2(msb) + DB.substr(2);

	var salt = sLen > 0 ? DB.substr(-sLen*2) : "";

	// check DB
	for (var i = 0; i < emLen - sLen - hLen - 2; i++) {
	    if (DB.substr(i*2,2) != "00") {
    		console.log("db != 00");
	        return false;
	    }
	}

	console.log("DB:"+DB);
	console.log("salt:"+salt);
	console.log("mHash:"+mHash);

	return H == hash("0000000000000000" + mHash + salt);
}
