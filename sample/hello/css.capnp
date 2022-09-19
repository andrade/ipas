@0xdaf4e052ef10ec25;

enum CSSMessageStatus {
	success  @0;    # all OK
	failure  @1;    # generic catch-all error
	internal @2;    # internal error
	invalid  @3;    # invalid request
}

struct M1Q {
	enclave     @0 :Data;
	untrusted   @1 :Data;

	aExGroup    @2 :Data;
	aGroup      @3 :Data;
	aPublic     @4 :Data;
}

struct M2P {
	status              @0 :CSSMessageStatus = failure;

	bExGroup            @1 :UInt32;
	bPublic             @2 :Data;

	aStatusCode         @3 :UInt32 = 600;
	aSigRL              @4 :Data;
}

struct M3Q {
	status      @0 :CSSMessageStatus = failure;

	aQuote      @1 :Data;
}

struct M4P {
	status      @0  :CSSMessageStatus = failure;

	aStatusCode @1  :UInt32 = 600;
	aRequestId  @2  :Text;              # Request-ID
	aReportSig  @3  :Text;              # X-IASReport-Signature
	aCertChain  @4  :Text;              # X-IASReport-Signing-Certificate
	aReport     @5  :Text;              # Attestation Verification Report

	bStatusCode @6  :UInt32 = 600;
	bRequestId  @7  :Text;
	bReportSig  @8  :Text;
	bCertChain  @9  :Text;
	bReport     @10 :Text;

	data        @11 :Data;
	mac         @12 :Data;
}

struct M11Q {
	iv          @0  :Data;
	ct          @1  :Data;              # encrypted client secret key + nonce
	tag         @2  :Data;
}

struct M12P {
	status      @0  :CSSMessageStatus = failure;

	data        @1  :Data;              # sealed client secret key + nonce
	mac         @2  :Data;
}

struct M21Q {
	nonce       @0  :Data;
	data        @1  :Data;              # sealed client secret key + nonce
	mac         @2  :Data;
}

struct M22P {
	status      @0  :CSSMessageStatus = failure;

	iv          @1  :Data;
	ct          @2  :Data;              # encrypted client secret key + nonce
	tag         @3  :Data;
}

struct CSSMessage {
	union {
		empty @0 :Void;
		m1    @1 :M1Q;
		m2    @2 :M2P;
		m3    @3 :M3Q;
		m4    @4 :M4P;
		m11   @5 :M11Q;
		m12   @6 :M12P;
		m21   @7 :M21Q;
		m22   @8 :M22P;
	}
}
