/**
 !!!!!!!!!!!!!!!!!!!!!!!!! WARNING !!!!!!!!!!!!!!!!!!!!!!!!!
 THIS CODE IS INSECURE AND NOT TO BE USED FOR ACTUAL CRYPTO!!!
 IT IS ALSO INEFFICIENT AND COBBLED TOGETHER IN ONE DAY!!! DO NOT USE IT!!
 It was written by Leo Reyzin as a reference implementation only, in order to generate test vectors.
 */

/*
 This is free and unencumbered software released into the public domain.
 
 Anyone is free to copy, modify, publish, use, compile, sell, or
 distribute this software, either in source code form or as a compiled
 binary, for any purpose, commercial or non-commercial, and by any
 means.
 
 In jurisdictions that recognize copyright laws, the author or authors
 of this software dedicate any and all copyright interest in the
 software to the public domain. We make this dedication for the benefit
 of the public at large and to the detriment of our heirs and
 successors. We intend this dedication to be an overt act of
 relinquishment in perpetuity of all present and future rights to this
 software under copyright law.
 
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 OTHER DEALINGS IN THE SOFTWARE.
 
 For more information, please refer to <http://unlicense.org>
 */

/**
 !!!!!!!!!!!!!!!!!!!!!!!!! WARNING !!!!!!!!!!!!!!!!!!!!!!!!!
 THIS CODE IS INSECURE AND NOT TO BE USED FOR ACTUAL CRYPTO!!!
 IT IS ALSO INEFFICIENT AND COBBLED TOGETHER JUST TO GET IT WORKING!!! DO NOT USE IT!!!
 It was written by Leo Reyzin as a reference implementation only, in order to generate test vectors.
 */

#include <NTL/ZZ_pXFactoring.h>
#include <NTL/ZZXFactoring.h>
#include "sha256.h"

NTL_CLIENT

static ZZ p, q;
static ZZ_p a, b, minus_b_over_a;

unsigned char hexToNum(unsigned char in) {
    if ('0'<=in && in<='9') return in-'0';
    if ('A'<=in && in<='F') return in-'A'+10;
    return in-'a'+10;
    
}
unsigned char numToHex(unsigned char in, bool upperCase) {
    if (in<10) return in+'0';
    return in-10 + (upperCase ? 'A' : 'a');
}




class pointP256 {
    // curve is y^2 = x^3+ax+b
public:
    ZZ_p x;
    ZZ_p y;
    bool isInf;
    
    pointP256 () {
        isInf = true;
    }
    
    pointP256 (const ZZ_p & _x, const ZZ_p & _y) {
        x = _x;
        y = _y;
        isInf = false;
    }
    
 
    bool isInfinity () const {
        return isInf;
    }
    
    bool onCurve() {
        return isInf || y*y == x*x*x+a*x+b;
    }
    
    pointP256 operator+(const pointP256 & b) const {
        // from http://www.secg.org/sec1-v2.pdf section 2.2.1
        if (b.isInf) return *this;
        if (isInf) return b;
        if (x == b.x) {
            if (y==b.y) { // point doubling
                ZZ_p lambda = (3*x*x+a)/(2*y);
                ZZ_p _x = lambda*lambda-x-x;
                ZZ_p _y = lambda*(x-_x)-y;
                return pointP256(_x, _y);
            }
            else { // infinity
                return pointP256();
            }
        }
        ZZ_p lambda = (b.y-y)/(b.x-x);
        ZZ_p _x = lambda*lambda-x-b.x;
        ZZ_p _y = lambda*(x-_x)-y;
        return pointP256(_x, _y);
    }
    pointP256 operator-() const {
        return pointP256(x, -y);
    }
    pointP256 operator-(const pointP256 & b) const {
        return *this+(-b);
    }
    
    pointP256 operator*(const ZZ & scalar) {
        pointP256 result;
        // simple double-and-add
        for (int i = NumBits(scalar)-1; i>=0; i--) {
            result = result+result;
            if (bit (scalar, i))
                result = result + *this;
        }
        return result;
    }
    
    bool operator==(pointP256 that) {
        return x==that.x && y==that.y && isInf == that.isInf;
    }
    
};

static pointP256 B;


class str {
public:
    unsigned char * s;
    int len;
    
    // NOTE: REQUIRES SOURCE AND DESTINATION TO BE NONOVERLAPPING
    static void reverse (unsigned char * dest, unsigned char * source, int len) {
        if ((dest<=source && dest+len>source) || (source<=dest && source+len>dest) ) {
            cout<<"CAN'T USE REVERSE WITH OVERLAPPING SOURCE AND DESTINATION\n";
            exit(-1);
        }
        for (int i = 0; i<len; i++){
            dest[i] = source[len-1-i];
        }
    }
    
    // From C string -- a factory constructor
    static str fromCString(const char * input) {
        str ret;
        ret.len = strlen(input);
        ret.s = new unsigned char[ret.len];
        for(int i=0; i<ret.len; i++) ret.s[i] = input[i];
        return ret;
    }
    
    // From hex string
    str(const char *  input) {
        len = strlen(input)/2;
        s = new unsigned char[len];
        for (int i = 0; i<strlen(input); i+=2) {
            s[i/2] = hexToNum(input[i])*16+hexToNum(input[i+1]);
        }
    }
    
    // From a single octet
    str(unsigned char c) {
        len = 1;
        s = new unsigned char[len];
        s[0]=c;
    }
    
    // From a single octet, repeated num times
    str(unsigned char c, int num) {
        len = num;
        s = new unsigned char[len];
        for (int i=0; i<len; i++) {
            s[i]=c;
        }
    }

    // from an EC point
    str(const pointP256 & p) {
        if (p.isInfinity()) {
            len = 1;
            s = new unsigned char[len];
            s[0] = 0;
        }
        else {
            len = 33;
            s = new unsigned char[len];
            unsigned char * r = new unsigned char[32];
            BytesFromZZ(r, conv<ZZ>(p.x), 32);
            reverse(s+1, r, 32);
            delete [] r;
            s[0] = 2+bit(conv<ZZ>(p.y), 0);
        }
    }
    
    // from a big int -- big-endian
    str(const ZZ & n, int nlen) {
        len = nlen;
        unsigned char * r = new unsigned char[len];
        BytesFromZZ(r, n, nlen);
        s = new unsigned char[len];
        reverse(s, r, len);
        delete [] r;
    }
    
    // from str -- slice
    str slice(int begin, int end) const {
        str ret;
        ret.len = end-begin;
        ret.s = new unsigned char[ret.len];
        memcpy(ret.s, this->s+begin, ret.len);
        return ret;
    }
    
    str strxor(const str & that) const {
        if (len != that.len) cout<<"ERROR -- XOR APPLIED TO STRINGS OF DIFFERENT LENGTHS\n";

        str ret;
        ret.len = len;
        ret.s = new unsigned char[len];
        for (int i=0; i<len; i++) {
            ret.s[i] = s[i]^that.s[i];
        }
        return ret;
    }
    
    str hash() const {
        str ret;
        ret.len = 32;
        ret.s = new unsigned char[ret.len];
        SHA256_CTX ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, s, len);
        sha256_final(&ctx, ret.s);
        return ret;
    }
    
    str HMAC(const str & K) const {
        str ret;
        ret.len = 32;
        ret.s = new unsigned char[ret.len];
        str L =(K.len>32) ? K.hash() : K;
        SHA256_CTX ctx;
        sha256_init(&ctx);
        int i;
        for (i = 0; i<L.len; i++) {
            unsigned char sym = L.s[i]^(unsigned char)0x36; // ipad
            sha256_update(&ctx, &sym, 1);
        }
        for (; i<64; i++) {
            unsigned char sym = (unsigned char)0x36; // ipad after key runs out
            sha256_update(&ctx, &sym, 1);
        }
        sha256_update(&ctx, s, len);
        unsigned char temp[32];
        sha256_final(&ctx, temp);

        sha256_init(&ctx);
        for (i = 0; i<L.len; i++) {
            unsigned char sym = L.s[i]^(unsigned char)0x5C; // opad
            sha256_update(&ctx, &sym, 1);
        }
        for (; i<64; i++) {
            unsigned char sym = (unsigned char)0x5C; // opad after key runs out
            sha256_update(&ctx, &sym, 1);
        }
        sha256_update(&ctx, temp, 32);
        sha256_final(&ctx, ret.s);
        return ret;
    }
    
    // empty
    str() {
        s = NULL;
        len = 0;
    }

    str (const str& that) {
        len = that.len;
        s = new unsigned char [len];
        memcpy(s, that.s, len);
    }
    
    str & operator=(const str& that) {
        if (s!=NULL) {
            delete []s;
        }
        len = that.len;
        s = new unsigned char [len];
        memcpy(s, that.s, len);
        return *this;
    }
    
    ~str () {
        if (s!=NULL) {
            delete[] s;
        }
    }
    
    // concatenate
    str operator||(const str & that) const {
        str ret;
        ret.len = this->len+that.len;
        ret.s = new unsigned char[ret.len];
        memcpy(ret.s, this->s, this->len);
        memcpy(ret.s+this->len, that.s, that.len);
        return ret;
        
    }

    // concatenate with a single character
    str operator||(char c) const {
        str ret;
        ret.len = this->len+1;
        ret.s = new unsigned char[ret.len];
        memcpy(ret.s, this->s, this->len);
        ret.s[len]=c;
        return ret;
    }

    // to hex string (lowercase)
    char * toHexString() const {
        char * ret = new char[len*2+1];
        for (int i = 0; i<len; i++) {
            ret[2*i] = numToHex(s[i]/16, false);
            ret[2*i+1] = numToHex(s[i]%16, false);
        }
        ret[2*len] ='\0';
        return ret;
    }
    
    // to integer -- big-endian
    ZZ toZZ() const {
        unsigned char * r = new unsigned char [len];
        reverse (r, s, len);
        ZZ ret;
        ZZFromBytes(ret, r, len);
        delete [] r;
        return ret;
    }
    
    // to EC point
    pointP256 toECPoint(bool & isValid) const {
        if (len == 1) {
            if (s[0]==0) { // infinity
                isValid = true;
                return pointP256();
            }
        }
        if (len != 33 || (s[0]!=02 && s[0]!=03)) {
            cout<<"ERROR -- CAN'T CONVERT TO EC POINT\n";
            exit(-1);
        }
        
        ZZ xint = this->slice(1, 33).toZZ();
        ZZ_p x = conv<ZZ_p>(xint);
        ZZ_p ysquared = x*x*x+a*x+b;
        if (Jacobi(conv<ZZ>(ysquared), p) != 1) {
            isValid = false;
            return pointP256();
        }
        ZZ_p y = power(ysquared, (p+1)/4);
        if ((s[0]&1) != bit(conv<ZZ>(y), 0)) y = -y;
        isValid = true;
        pointP256 ret(x, y);
        if (!ret.onCurve()) {
            cout<<"CONVERSION BUG!!!";
            exit(-1);
        }
        return ret;
    }
    
    // case insensitive
    bool operator == (const char * hexString) {
        char * temp = this->toHexString();
        int i;
        for (i = 0; temp[i]!='\0' && hexString[i]!='\0'; i++) {
            if (tolower(temp[i])!=tolower(hexString[i])) return false;
        }
        return temp[i]==hexString[i];
    }
    bool operator != (const char * hexString) {
        return ! (*this==hexString);
    }
};

ostream& operator<<(ostream& os, const str& s)
{
    os << s.toHexString();
    return os;
}


static str ECVRF_DST;
static str SSWU_TEST_DST;

void initialize() {
    ZZ powerOf2;
    power2(p, 256);
    power2(powerOf2, 224);
    p-=powerOf2;
    power2(powerOf2, 192);
    p+=powerOf2;
    power2(powerOf2, 96);
    p+=powerOf2;
    power2(powerOf2, 0);
    p-=powerOf2;
    
    ZZ_p::init(p);
    
    a = conv<ZZ_p>(conv<ZZ>( "115792089210356248762697446949407573530086143415290314195533631308867097853948"));
    
    b =
    conv<ZZ_p>(conv<ZZ>( "41058363725152142129326129780047268409114441015993725554835256314039467401291"));
    minus_b_over_a = -b/a;

    q = conv<ZZ>( "115792089210356248762697446949407573529996955224135760342422259061068512044369");
    B = pointP256(conv<ZZ_p>("48439561293906451759052585252797914202762949526041747995844080717082404635286"), conv<ZZ_p>("36134250956749795798585127919587881956611106672985015071877198253568414405109"));
    
    ECVRF_DST = str::fromCString("ECVRF_P256_XMD:SHA-256_SSWU_NU_") || '\2';
    SSWU_TEST_DST = str::fromCString("P256_XMD:SHA-256_SSWU_NU_TESTGEN");
}

ZZ Nonce_Generation(const str & sk_string, const str & h_string) {
    str h1 = h_string.hash();
    str reduced_h1 = str((h1.toZZ() % q), 32);
    str V(0x01, 32);
    str K(0x00, 32);
    K = (V || '\0' || sk_string || reduced_h1).HMAC(K);
    V = V.HMAC(K);
    K = (V || '\1' || sk_string || reduced_h1).HMAC(K);
    V = V.HMAC(K);
    ZZ ret;
    while(true) {
        V = V.HMAC(K);
        ret = V.toZZ();
        if (ret>0 && ret<q) return ret;
        K = (V || '\0').HMAC(K);
        V = V.HMAC(K);
    }
}

str ECDSA_Sign(const str & SK, const str & M) {
    // From https://tools.ietf.org/html/rfc6979#section-2.4
    ZZ k = Nonce_Generation(SK, M);
    ZZ r =  conv<ZZ>((B*k).x) % q;
    ZZ s;
    {
        // change the modulus to q
        ZZ_pPush push(q);
        ZZ_p smod = ((conv<ZZ_p>(M.hash().toZZ())+conv<ZZ_p>(SK.toZZ())*conv<ZZ_p>(r)))/conv<ZZ_p>(k);
        s = conv<ZZ>(smod);
        // At this point push will get destroyed, will bring the modulus back to p
    }
    return str(r,32) || str(s, 32);
}

str ECDSA_KeyGen(const str & SK) {
    return str(B*SK.toZZ());
}

pointP256 Try_And_Increment(const str & pk_string, const str & alpha_string, bool verbose) {
    ZZ ctr(0);
    str suite_string = str('\1');
    for (;; ctr++) {
        str h_string = str('\2') || (suite_string || '\1' || pk_string || alpha_string || str(ctr, 1) || '\0').hash();

        bool isValid;
        pointP256 H = h_string.toECPoint(isValid);
        if (isValid) {
            if (verbose) cout << "try_and_increment succeded on ctr = " << ctr << " <vspace />" << endl;
            return H;
        }
    }
}


ZZ_p SSWU_hash_to_field(const str & string_to_hash, const str & DST, bool verbose) {
    int len_in_bytes = 48; // L=(256+128)/8; m==1; L==1
    str l_i_b_str = str(ZZ(len_in_bytes),2);
    str Z_pad = str('\0', 64);
    str DST_prime = DST || (unsigned char)DST.len;

    str b_0 = (Z_pad || string_to_hash || l_i_b_str || '\0' || DST_prime).hash();
    str b_1 = (b_0 || '\1' || DST_prime).hash();
    str b_2 = (b_0.strxor(b_1) || '\2' || DST_prime).hash();
    str uniform_bytes =  (b_1 || b_2).slice(0,len_in_bytes);
    if (verbose) cout << "In SSWU: uniform_bytes = " << uniform_bytes << " <vspace />" << endl;
    ZZ u_int = uniform_bytes.toZZ();
    ZZ_p u = conv<ZZ_p>(u_int);
    if (verbose) cout << "In SSWU: u = " << str(conv<ZZ>(u), 32) << " <vspace />" << endl;
    return u;
}

pointP256 SSWU_map_to_curve(const ZZ_p & u, bool verbose) {
    ZZ_p Z = conv<ZZ_p>(ZZ(-10));
    ZZ_p Z_times_u_squared = Z*u*u;
    ZZ_p tv1_inverse = Z_times_u_squared+Z_times_u_squared*Z_times_u_squared;
    ZZ_p tv1 = IsZero(tv1_inverse) ? tv1_inverse : inv(tv1_inverse);
    ZZ_p x = minus_b_over_a*(1+tv1);
    if (IsZero(tv1)) x = b/(Z*a);
    if (verbose) cout << "In SSWU: x1 = " << str(conv<ZZ>(x), 32) << " <vspace />" << endl;
    ZZ_p gx1 = x*x*x + a*x + b;
    if (Jacobi(conv<ZZ>(gx1), p) == 1) {
        if (verbose) cout<< "In SSWU: gx1 is a square <vspace />" << endl;
    }
    else {
        if (verbose) cout<< "In SSWU: gx1 is a nonsquare <vspace />" << endl;
        x = Z_times_u_squared*x;
    }

    bool isValid;
    // The sign of the resulting y is not important right now, because we will make it match the sign of u
    pointP256 H = (str('\2') || str(conv<ZZ>(x), 32)).toECPoint(isValid);
    if (!isValid) {
        cout<<"SSWU error"<<endl;
        exit(-1);
    }
    // make the signs of u and y match
    if (bit(conv<ZZ>(u), 0)!=bit(conv<ZZ>(H.y), 0)) H.y = -H.y;
    
    return H;
}

pointP256 SSWU(const str & pk_string, const str & alpha_string, const str & DST, bool verbose) {
    return SSWU_map_to_curve ( SSWU_hash_to_field (pk_string || alpha_string, DST, verbose), verbose);
}

ZZ ECVRF_Hash_Points(const pointP256 & p1, const pointP256 & p2, const pointP256 & p3, const pointP256 & p4, str suite_string) {
    return (suite_string || '\2'  || str(p1) || str(p2) || str(p3) || str(p4)  || '\0').hash().slice(0,16).toZZ();
}


str ECVRF_Prove(const str & SK, const str & alpha_string, bool useSSWU, bool verbose) {
    // Secret Scalar
    ZZ x = SK.toZZ();
    // public key
    str PK(B*x);
    
    // hash to curve
    pointP256 H = useSSWU ? SSWU(PK, alpha_string, ECVRF_DST, verbose) : Try_And_Increment(PK, alpha_string, verbose);
    
    if (verbose) cout << "H = " << str(H) << " <vspace />" << endl;

    
    pointP256 Gamma = H*x;
    ZZ k = Nonce_Generation(SK, str(H));
    if (verbose) cout << "k = " << str(k, 32) << " <vspace />" << endl;
    
    pointP256 U = B*k;
    pointP256 V = H*k;
    if (verbose) cout << "U = k*B = " << str(U) << " <vspace />" << endl;
    if (verbose) cout << "V = k*H = " << str(V) << " <vspace />" << endl;

    str suite_string = str(useSSWU? '\2' : '\1');
    ZZ c = ECVRF_Hash_Points(H, Gamma, U, V, suite_string);
    ZZ s = (k+c*x) % q;

    str proof = str(Gamma) || str(c, 16) || str(s, 32);
    if (verbose) cout << "pi = " << proof << " <vspace />" << endl;
    
    if (verbose) cout << "beta = " << (suite_string || '\3' || str(Gamma)  || '\0').hash();

    return proof;
}

bool ECVRF_Verify(const str & proof, const str & PK, const str & alpha_string, bool useSSWU) {
    
    
    // get the pk
    bool isValid;
    pointP256 Y = PK.toECPoint(isValid);
    if (!isValid) return false;
    
    // parse the proof
    pointP256 Gamma = proof.slice(0, 33).toECPoint(isValid);
    ZZ c = proof.slice(33, 49).toZZ();
    ZZ s = proof.slice(49, 81).toZZ();

    // Hash to curve
    pointP256 H = useSSWU ? SSWU(PK, alpha_string, ECVRF_DST, false) : Try_And_Increment(PK, alpha_string, false);

    // Hash points
    str suite_string = str(useSSWU? '\2' : '\1');
    ZZ cprime = ECVRF_Hash_Points(H, Gamma, B*s-Y*c, H*s-Gamma*c, suite_string);
    
    return c==cprime;
    
}

void generateTestVector(const char * sk_input, const char * M_input, bool useSSWU) {
    str SK(sk_input);
    cout<<"<t>"<<endl;
    cout << "SK = x = " << str(SK) << " <vspace />" << endl;
    cout << "PK = " << B*SK.toZZ() << " <vspace />" << endl;
    str M = str::fromCString(M_input);
    cout << "alpha = " << M << " (ASCII \"";
    for (int i=0; i<M.len; i++) cout<< M.s[i];
    cout <<"\") <vspace />" << endl;
    str proof = ECVRF_Prove(SK, M, useSSWU, true);
    cout<<"</t>"<<endl;
}

void testECDSAExample (const char * sk_input, const char* M_input, const char * pk_value,  const char* sig_value,const char* proofNoSSWU_value, const char* proofSSWU_value) {
   
    str SK(sk_input);
    str PK = ECDSA_KeyGen(SK);
    
    if (PK!=pk_value) {
        cout<<endl<<"ERROR: PK = ";
        cout<<endl;
        cout << PK;
        cout<<pk_value;
        cout<<endl;
        exit(-1);
    }
    
    str M=str::fromCString(M_input);

    if (sig_value!=NULL) {
        str sig = ECDSA_Sign(SK, M);
    
        if (sig!=sig_value) {
            cout<<endl<<"ERROR: Sig = ";
            cout<<sig;
            cout<<endl;
            exit(-1);
        }
    }

    // Now evaluate the VRF on the same example and test the result
    str proof = ECVRF_Prove(SK, M, false, false); // no SSWU
    if(proof!=proofNoSSWU_value) {
        cout<<endl<<"ERROR: ProofNoSSWU = ";
        cout<<proof;
        cout<<endl;
        exit(-1);
    }
    if(!ECVRF_Verify(proof, PK, M, false)) {
        cout<<endl<<"ERROR: Verification no SSWU"<<endl;
        exit(-1);
    }

    proof = ECVRF_Prove(SK, M, true, false); // yes SSWU
    if(proof!=proofSSWU_value) {
        cout<<endl<<"ERROR: ProofSSWU = ";
        cout<<proof;
        cout<<endl;
        exit(-1);
    }
    if(!ECVRF_Verify(proof, PK, M, true)) {
        cout<<endl<<"ERROR: Verification yes SSWU"<<endl;
        exit(-1);
    }
    
}

bool testSSWUExample (const char * M_input, const char * u, const char * x, const char * y) {
    ZZ_p u_res = SSWU_hash_to_field(str::fromCString(M_input), SSWU_TEST_DST, false);
    if (conv<ZZ>(u_res) != str(u).toZZ()) {
        cout << "ERROR SSWU_hash_to_field on example \"" << M_input << "\"" << endl;
        return false;
    }
    else {
        pointP256 output = SSWU_map_to_curve(u_res, false);
        if (conv<ZZ>(output.x) != str(x).toZZ() || conv<ZZ>(output.y) != str(y).toZZ()) {
            cout << "ERROR SSWU_hash_to_field on example \"" << M_input << "\"" << endl;
            return false;
        }
    }
    return true;
}

void testSSWU() {
    /* These test vectors are from CFRG hash-to-curve draft https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve/blob/8ec5a3fdcbfc05d00ab18aa419ddfc895cb5b686/draft-irtf-cfrg-hash-to-curve.md#p256_xmdsha-256_sswu_nu_ */
    testSSWUExample("",
                      "8edbab803386a426e41ed452e269ecaf7963fcf2428572122fd806f8124a74c1",
                      "2063ed79bfbd8dcb7ee0ea2f3a0859490e314bc44c52818810e7050fc2fef9d2",
                      "b1b8d127e418d55f3e24aff4dd3b93f87b0f9010b57750ae5364369a282b0c01");
    testSSWUExample("abc",
                      "5e62db94e1b65baef703b29e9ec76229d425ec11f68fd2826650892e94f41617",
                      "fa966fde8359c530de36964554878add0d66ab91a4941c778a6ca2ef940f51da",
                      "a443c5d7acb4584c5482744d7c277c402f974ecb3c5a9e6cc32891a7d4395cc1"
                      );
    testSSWUExample("abcdef0123456789",
                      "2b65b29127cfcc0d932b0353989def6f9eff7d8fc439b24ba96a3316d5b9c51e",
                      "1f629999e7ae72560ef6753c174e59e8cbb8012dd19ab422e07c438dcf50496c",
                      "307d198488b34f1c901b83e80eac513a91b2deb18723bb971adb7dca8e3d406a"
                      );
   testSSWUExample("a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                     "0fb249d711473b504acf7a1e6a87e31d26f4a7aec11ff673e7ae3b80f421b958",
                     "191231cd9517dfa132816a24860f55db605e4f5a190ffebf0b9bbb232fd5ae88",
                     "f4aa03d54f7c2da1da7d597678825bc929d339d1c9bf43edfe1461b7c4862ce2"
                     );

}

void testECDSAandECVRF () {
    // Examples are from https://tools.ietf.org/html/rfc6979#appendix-A.2.5; vrf values are our own
    
    testECDSAExample("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
                     "sample",
                     "0360FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6",
                     "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8",
                     "035b5c726e8c0e2c488a107c600578ee75cb702343c153cb1eb8dec77f4b5071b498e7c291a16dafb9ccff8c2ae1f039fa92a328d5f7e0d483ee18353067a13f699944a78892ff24939bcd044827eef884",
                     "0331d984ca8fece9cbb9a144c0d53df3c4c7a33080c1e02ddb1a96a365394c7888a39dfe7432f119228473f37db3f87ca470c63b0237432a791f18f823c1215e276b7ac0962725ba8daec2bf90c0ccc91a");
    testECDSAExample("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
                     "test",
                     "0360FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6",
                     "F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083",
                     "034dac60aba508ba0c01aa9be80377ebd7562c4a52d74722e0abae7dc3080ddb56c874cc95b7d29a6a65cb518fe6f4418256385f12b1eccbad023c901bb983ff707b109b3a3b526ca3a1e8661f7b8481a2",
                     "03f814c0455d32dbc75ad3aea08c7e2db31748e12802db23640203aebf1fa8db2721e0499b7cecd68027a82f6095da076625a5f2f62908f1c283d5ee9b9e852d85bedf64f2452a4e5094729e101824443e");
    
    // This example is from ANSI X9.62 2005 L.4.2
    ZZ ANSIX962sk =  conv<ZZ>("20186677036482506117540275567393538695075300175221296989956723148347484984008");
    str ANSIX962SK(ANSIX962sk, 32);

    testECDSAExample (ANSIX962SK.toHexString(),
                      "Example using ECDSA key from Appendix L.4.2 of ANSI.X9-62-2005",
                      "03596375E6CE57E0F20294FC46BDFCFD19A39F8161B58695B3EC5B3D16427C274D",
                      NULL,
                      "03d03398bf53aa23831d7d1b2937e005fb0062cbefa06796579f2a1fc7e7b8c6679d92353c8a4fdfddb2a8540094b686cb5fb50f730d833a098a0399ccad32f3fec4da2299891fc75ebda42baeb65e8c11",
                      "039f8d9cdc162c89be2871cbcb1435144739431db7fab437ab7bc4e2651a9e99d5288aac70a5e4bd07df303c1d460eb6336bb5fa95436a07c2f6b7aec6fef7cc4846ea901ee1e238dee12bf752029b0b2e"
                      );
    
}


void generateVectors() {
    // This example is from ANSI X9.62 2005 L.4.2
    ZZ ANSIX962sk =  conv<ZZ>("20186677036482506117540275567393538695075300175221296989956723148347484984008");
    str ANSIX962SK(ANSIX962sk, 32);

  
    cout<<"<section title=\"ECVRF-P256-SHA256-TAI\">"<<endl;
    cout<<"<t>These two example secret keys and messages are taken from Appendix A.2.5 of <xref target=\"RFC6979\"/>.</t>"<<endl;
    generateTestVector("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
                       "sample", false);
    generateTestVector("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
                       "test", false);
    
    cout<<"<t>This example secret key is taken from Appendix L.4.2 of <xref target=\"ANSI.X9-62-2005\"/>.</t>"<<endl;

    generateTestVector(ANSIX962SK.toHexString(),
                       "Example using ECDSA key from Appendix L.4.2 of ANSI.X9-62-2005", false);

    cout<<"</section>"<<endl;
    cout<<"<section title=\"ECVRF-P256-SHA256-SSWU\">"<<endl;
    cout<<"<t>These two example secret keys and messages are taken from Appendix A.2.5 of <xref target=\"RFC6979\"/>.</t>"<<endl;
    
    generateTestVector("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
                       "sample", true);
    generateTestVector("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
                       "test", true);
    
    cout<<"<t>This example secret key is taken from Appendix L.4.2 of <xref target=\"ANSI.X9-62-2005\"/>.</t>"<<endl;
    generateTestVector(ANSIX962SK.toHexString(),
                       "Example using ECDSA key from Appendix L.4.2 of ANSI.X9-62-2005", true);
    cout<<"</section>"<<endl;
}

int main()
{
    
    initialize();
    testSSWU();
    testECDSAandECVRF();
    generateVectors();
    
}
