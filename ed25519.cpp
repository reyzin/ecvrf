/**
 !!!!!!!!!!!!!!!!!!!!!!!!! WARNING !!!!!!!!!!!!!!!!!!!!!!!!!
 THIS CODE IS INSECURE AND NOT TO BE USED FOR ACTUAL CRYPTO!!!
 IT IS ALSO INEFFICIENT AND COBBLED TOGETHER JUST TO GET IT WORKING!!! DO NOT USE IT!!!
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
#include "sha512.h"

NTL_CLIENT

static ZZ p, q, cofactor;
static ZZ_p A, d, sqrt_minus_A_plus_2;

unsigned char hexToNum(unsigned char in) {
    if ('0'<=in && in<='9') return in-'0';
    return in-'a'+10;
    
}
unsigned char numToHex(unsigned char in, bool upperCase) {
    if (in<10) return in+'0';
    return in-10 + (upperCase ? 'A' : 'a');
}


void printArray(const unsigned char *  input, int iLen) {
    for (int i = 0; i<iLen; i++) {
        printf("%02x", input[i]);
    }
}


class pointEd25519 {
    /*
     curve is -x^2+y^2 = 1+dx^2y^2, where d = -121665/121666
     encoding: edwards. y followed by x parity bit. Point at infinity: y = 1, x = 0.
     birationally equivalent to montgomery:
     (we will use coordinates (u, v) for Montgomery, and the equation v^2 = u(u^2 + Au + 1), where A = 486662)
     (in Mongomery, we store only u as PK).
     Conversion x=(u/v) * sqrt_minus_A_plus_2,y=(u-1)/(u+1) (where minus_A_plus_2 = -486664)
     To go back: u = (1+y)/(1-y), v = sqrt_minus_A_plus_2*u/x, whenever (x, y) is not the point at infinity).
     */

public:
    ZZ_p x;
    ZZ_p y;
    
    pointEd25519 () {
        x = 0;
        y = 1;
    }
    
    pointEd25519 (const ZZ_p & _x, const ZZ_p & _y) {
        x = _x;
        y = _y;
    }
    
    pointEd25519 (const unsigned char * a) {
        pointEd25519 *t = string_to_point(a);
        if (t==NULL) {
            cout<<"NULL STRING TO POINT\n";
            exit(-1);
        }
        this->x = t->x;
        this->y = t->y;
        delete t;
    }
    static pointEd25519 * string_to_point(const unsigned char * a) {
        pointEd25519 * ret;
        unsigned char b[32];
        b[31] = a[31] & 0x7F;
        for (int i = 0; i<31; i++){
            b[i] = a[i];
        }
        ZZ inty;
        ZZFromBytes(inty, b, 32);
        ZZ_p y = conv<ZZ_p>(inty);
        // From https://tools.ietf.org/html/rfc8032#section-5.1.3
        ZZ_p u = y*y-1;
        ZZ_p v = d*y*y+1;
        ZZ_p x = power(u/v, (p+3)/8);
        if (v*x*x != u) {
            if (v*x*x != -u) {
                return NULL;
            }
            x = x * power(ZZ_p(2), (p-1)/4);
        }
        if (x==0 && (a[31]&0x80)!=0) {
            return NULL;
        }
        if (bit(conv<ZZ>(x), 0) != (a[31]>>7)) {
            x=-x;
        }
        ret = new pointEd25519(x, y);
        if (!ret->onCurve()) {
            cout << "ERROR: DECODING BUG!!!";
        }
        return ret;
    }
    
    bool isInfinity () {
        return IsZero(x) && IsOne(y);
    }
    
    void toBytes (unsigned char *a) const  {
        BytesFromZZ(a, conv<ZZ>(y), 32);
        a[31] |= bit(conv<ZZ>(x), 0)<<7;
    }
    
    bool onCurve() {
        ZZ_p ys = y*y;
        ZZ_p xs = x*x;
        return ys-xs == 1+d*xs*ys;
    }
    
    pointEd25519 operator+(const pointEd25519 & b) const {
        // x = (x1y2+x2y1)/(1+dx1x2y1y2) // From https://ed25519.cr.yp.to/ed25519-20110926.pdf p. 6
        // y = (y1y2+x1x2)/(1-dx1x2y1y2)
        ZZ_p denom = x*b.x*y*b.y*d;
        ZZ_p _x = (x*b.y+b.x*y)/(1+denom);
        ZZ_p _y = (y*b.y+x*b.x)/(1-denom);
        return pointEd25519(_x, _y);
    }
    pointEd25519 operator-() const {
        return pointEd25519(-x, y);
    }
    pointEd25519 operator-(const pointEd25519 & b) const {
        return *this+(-b);
    }
    
    pointEd25519 operator*(const ZZ & scalar) {
        pointEd25519 result;
        // simple double-and-add
        for (int i = NumBits(scalar)-1; i>=0; i--) {
            result = result+result;
            if (bit (scalar, i))
                result = result + *this;
        }
        return result;
    }
    
    bool operator==(pointEd25519 that) {
        return x==that.x && y==that.y;
    }
    
};

static pointEd25519 B;


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
    

    // From hex string -- little endian
    str(const char *  input) {
        len = strlen(input)/2;
        s = new unsigned char[len];
        for (int i = 0; i<strlen(input); i+=2) {
            s[i/2] = hexToNum(input[i])*16+hexToNum(input[i+1]);
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
    str(const pointEd25519 & p) {
        len = 32;
        s = new unsigned char[len];
        p.toBytes(s);
    }
    
    // from a big int, little-endian
    str(const ZZ & n, int nlen) {
        len = nlen;
        s = new unsigned char[len];
        BytesFromZZ(s, n, nlen);
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
        ret.len = 64;
        ret.s = new unsigned char[ret.len];
        mbedtls_sha512_ret(s, len, ret.s, 0);
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
    
    // to integer, little-endian
    ZZ toZZ() const {
        ZZ ret;
        ZZFromBytes(ret, s, len);
        return ret;
    }

    // to integer, big-endian
    ZZ toZZ_bigEndian() const {
        unsigned char * r = new unsigned char [len];
        reverse (r, s, len);
        ZZ ret;
        ZZFromBytes(ret, r, len);
        delete [] r;
        return ret;
    }

    
    // to EC point
    pointEd25519 toECPoint(bool & isValid) const {
        pointEd25519 ret;
        if(len!=32) {
            cout<<"ERROR -- CAN'T CONVERT TO EC POINT\n";
            exit(-1);
        }
        pointEd25519 *t = pointEd25519::string_to_point(s);
        if (t==NULL) {
            isValid = false;
        }
        else {
            isValid = true;
            ret.x = t->x;
            ret.y = t->y;
            delete t;
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

str EdDSA_Sign(const str & SK, const str & M) {
    // From https://tools.ietf.org/html/rfc8032#section-5.1.5
    str h = SK.hash();
    
    h.s[0]&=0xF8;
    h.s[31]&=0x7F;
    h.s[31]|=0x40;
    
    // secret scalar
    ZZ s = h.slice(0, 32).toZZ();
    str PK(B*s);
    
    ZZ r = (h.slice(32, 64) || M).hash().toZZ();
    
    pointEd25519 R = B*r;
    
    ZZ k = (str(R) || PK || M).hash().toZZ();
    
    ZZ S = (r+k*s) % q;
    return str(R) || str(S, 32);
}

str EdDSA_KeyGen(const str & SK) {
// From https://tools.ietf.org/html/rfc8032#section-5.1.6
    str h = SK.hash();

    h.s[0]&=0xF8;
    h.s[31]&=0x7F;
    h.s[31]|=0x40;
    
    ZZ s = h.slice(0, 32).toZZ();
    
    return str(B*s);
}

static str ECVRF_DST;
static str ELLIGATOR2_TEST_DST;
void initialize() {
    power2(p, 255);
    p-=19;
    ZZ_p::init(p);
    
    d=ZZ_p(-121665)/ZZ_p(121666);
    
    sqrt_minus_A_plus_2 = conv<ZZ_p>("6853475219497561581579357271197624642482790079785650197046958215289687604742");
    
    A = ZZ_p(486662);
    
    cofactor = ZZ(8);
    
    B = pointEd25519(conv<ZZ_p>("15112221349535400772501151409588531511454012693041857206046113283949847762202"), conv<ZZ_p>("46316835694926478169428394003475163141307993866256225615783033603165251855960"));
    
    power2(q, 252);
    q+=conv<ZZ>("27742317777372353535851937790883648493");

    ECVRF_DST = str::fromCString("ECVRF_edwards25519_XMD:SHA-512_ELL2_NU_") || '\4';
    ELLIGATOR2_TEST_DST = str::fromCString("edwards25519_XMD:SHA-512_ELL2_NU_TESTGEN");

}

pointEd25519 Try_And_Increment(const str & pk_string, const str & alpha_string, bool verbose) {
    str suite_string = str('\3');
    ZZ ctr(0);
    for (;; ctr++) {
        str h_string = (suite_string || '\1' || pk_string || alpha_string || str(ctr, 1) || '\0').hash();

        pointEd25519 * H = pointEd25519::string_to_point(h_string.s);
        if (H!=NULL) {
            pointEd25519 G = (*H)*cofactor;
            if (!G.isInfinity()) {
                delete H;
                if (verbose) cout << "            <li>try_and_increment succeeded on ctr = " << ctr << "</li>" << endl;
                return G;
            }
            delete H;
        }
    }
}


ZZ_p Elligator2_hash_to_field(const str & string_to_hash, const str & DST, bool verbose) {
    int len_in_bytes = 48; // L=(256+128)/8; m==1; L==1
    str l_i_b_str = str('\0') || (unsigned char)len_in_bytes; // manual, because this is big endian
    str Z_pad = str('\0', 128);
    str DST_prime = DST || (unsigned char)DST.len;

    str b_0 = (Z_pad || string_to_hash || l_i_b_str || '\0' || DST_prime).hash();
    str b_1 = (b_0 || '\1' || DST_prime).hash();
    str uniform_bytes =  b_1.slice(0, len_in_bytes);
    if (verbose) cout << "            <li>In Elligator2: uniform_bytes = " << uniform_bytes << "</li>" << endl;
    ZZ u_int = uniform_bytes.toZZ_bigEndian();
    ZZ_p u = conv<ZZ_p>(u_int);
    if (verbose) cout << "            <li>In Elligator2: u = " << str(conv<ZZ>(u), 32) << "</li>" << endl;
    return u;
}

pointEd25519 Elligator2_map_to_curve_and_clear_cofactor(const ZZ_p & input_field_element, bool verbose) {
    ZZ_p x1 = - A / (1 + 2*input_field_element*input_field_element); // this is the candidate Montgomery u coordinate
    ZZ_p gx = x1 * (x1*x1 + A*x1 + 1); // gx1 for now; may change to gx2 depending on Jacobi
    if (verbose) cout << "            <li>In Elligator2: gx1 = " << str(conv<ZZ>(gx), 32) << "</li>" << endl;
    int jacobi = Jacobi(conv<ZZ>(gx), p);
    ZZ_p montgomery_u; // this is the final Montgomery u coordinate; it's called x in hash-to-curve draft
    if (jacobi == 1) {
        if (verbose) cout<< "            <li>In Elligator2: gx1 is a square</li>" << endl;
        montgomery_u = x1;
    }
    else {
        if (verbose) cout << "            <li>In Elligator2: gx1 is a nonsquare</li>" << endl;
        montgomery_u = -A-x1;
        gx = montgomery_u * (montgomery_u*montgomery_u + A*montgomery_u + 1);
    }
    ZZ_p edwards_y = (montgomery_u-1)/(montgomery_u+1); // convert from Montgomery to Edwards via the birational map
    str H_string(conv<ZZ>(edwards_y), 32);
    bool isValid;
    pointEd25519 H = H_string.toECPoint(isValid);
    if (!isValid) {
        cout<<"Elligator2 error 1"<<endl;
        exit(-1);
    }
    // H now has the correct y coordinate; x coordinate may have the wrong sign
    // To find if the sign is correct, convert the x-coordinate to Montomery and check
    ZZ_p montgomery_v = sqrt_minus_A_plus_2*montgomery_u/H.x;
    // Sanity check: v should be the square root of gx
    if (montgomery_v*montgomery_v != gx) {
        cout<< "Elligator2 error 2"<<endl;
    }
    // Check if the sign needs to be changed
    int sgn0 = bit(conv<ZZ>(montgomery_v), 0);
    if ((jacobi == 1 && sgn0==0) || (jacobi == -1 && sgn0==1)) {
        H.x = -H.x;
    }
    // clear cofactor
    return H*cofactor;
}



pointEd25519 Elligator2(const str & pk_string, const str & alpha_string, const str & DST, bool verbose) {
    return Elligator2_map_to_curve_and_clear_cofactor ( Elligator2_hash_to_field (pk_string || alpha_string, DST, verbose), verbose);
}


ZZ EdVRF_Challenge_Generation(const pointEd25519 & p1, const pointEd25519 & p2, const pointEd25519 & p3, const pointEd25519 & p4, const pointEd25519 & p5, str suite_string) {
    return (suite_string || '\2' || str(p1) || str(p2) || str(p3) || str(p4) || str(p5) || '\0').hash().slice(0,16).toZZ();
}

str EdVRF_Prove(const str & SK, const str & alpha_string, bool useElligator2, bool verbose) {
    // From https://tools.ietf.org/html/rfc8032#section-5.1.5
    
    str h = SK.hash();
        
    h.s[0]&=0xF8;
    h.s[31]&=0x7F;
    h.s[31]|=0x40;

    // secret scalar
    ZZ x = h.slice(0, 32).toZZ();
    
    if (verbose) cout << "            <li>x = " << str(x, 32) << "</li>" << endl;
    
    // public key
    pointEd25519 Y = B*x;
    str PK(Y);

    // hash to curve
    pointEd25519 H = useElligator2 ? Elligator2(PK, alpha_string, ECVRF_DST, verbose) : Try_And_Increment(PK, alpha_string, verbose);
    
    if (verbose) cout << "            <li>H = " << str(H) << "</li>" << endl;

    pointEd25519 Gamma = H*x;

    // Nonce Generation
    str k_string = (h.slice(32,64) || str(H)).hash();
    if (verbose) cout << "            <li>k_string = " << str(k_string) << "</li>" << endl;
    ZZ k = k_string.toZZ() % q;
    if (verbose) cout << "            <li>k = " << str(k, 32) << "</li>" << endl;

    // Hash points
    pointEd25519 U = B*k;
    pointEd25519 V = H*k;
    if (verbose) cout << "            <li>U = k*B = " << str(U) << "</li>" << endl;
    if (verbose) cout << "            <li>V = k*H = " << str(V) << "</li>" << endl;

    str suite_string = str(useElligator2? '\4' : '\3');
    ZZ c = EdVRF_Challenge_Generation(Y, H, Gamma, U, V, suite_string);
    
    ZZ s = (k+c*x) % q;
    
    str proof = str(Gamma) || str(c, 16) || str(s, 32);
    if (verbose) cout << "            <li>pi = " << proof << "</li>" << endl;
    
    // proof_to_hash
    if (verbose) cout << "            <li>beta = " << (suite_string || '\3' || str(Gamma*cofactor) || '\0').hash() << "</li>" << endl;
    
    return proof;
}

bool EdVRF_Verify(const str & proof, const str & PK, const str & alpha_string, bool useElligator2) {
    
    // get the pk
    bool isValid;
    pointEd25519 Y = PK.toECPoint(isValid);
    if (!isValid) return false;
    
    // parse the proof
    pointEd25519 Gamma = proof.slice(0, 32).toECPoint(isValid);
    if (!isValid) return false;
    ZZ c = proof.slice(32, 48).toZZ();
    ZZ s = proof.slice(48, 80).toZZ();
    
    if (s>=q) return false;

    // Hash to curve
    pointEd25519 H = useElligator2 ? Elligator2(PK, alpha_string, ECVRF_DST, false) : Try_And_Increment(PK, alpha_string, false);

    // Hash points
    str suite_string = str(useElligator2? '\4' : '\3');
    ZZ cprime = EdVRF_Challenge_Generation(Y, H, Gamma, B*s-Y*c, H*s-Gamma*c, suite_string);
    
    return c==cprime;
    
}

void generateTestVector(const char * sk_input, const char * M_input, bool useElligator2) {
    str SK(sk_input);
    cout<<  "        <ul empty=\"true\" spacing=\"compact\">"<<endl;
    cout << "            <li>SK = " << str(SK) << "</li>" << endl;
    cout << "            <li>PK = " << EdDSA_KeyGen(SK) << "</li>" << endl;
    str M(M_input);
    cout << "            <li>alpha = " << M ;
    if(M.len == 0) cout << " (the empty string)";
    else if(M.len == 1) cout << " (1 byte)";
    else cout << " (" << M.len << " bytes)";
    cout <<"</li>" << endl;
    str proof = EdVRF_Prove(SK, str(M_input), useElligator2, true);
    cout<<"        </ul>"<<endl;
}

void testEdDSAExample (const char * sk_input,  const char* M_input, const char * pk_value, const char* sig_value, const char* proofNoElligator2_value, const char* proofElligator2_value) {
   
    str SK(sk_input);
    str PK = EdDSA_KeyGen(SK);
    
    if (PK!=pk_value) {
        cout<<endl<<"ERROR: PK = ";
        cout << PK;
        cout<<endl;
        cout<<pk_value;
        cout<<endl;
        exit(-1);
    }
    
    str M(M_input);
    
    str sig = EdDSA_Sign(SK, M);
    
    if (sig!=sig_value) {
        cout<<endl<<"ERROR: Sig = ";
        cout<<sig;
        cout<<endl;
        exit(-1);
    }

    // Now evaluate the VRF on the same example and test the result
    str proof = EdVRF_Prove(SK, M, false, false); // no elligator2
    if(proof!=proofNoElligator2_value) {
        cout<<endl<<"ERROR: ProofNoElligator2 = ";
        cout<<proof;
        cout<<endl;
        exit(-1);
    }
    if(!EdVRF_Verify(proof, PK, M, false)) {
        cout<<endl<<"ERROR: Verification no Elligator2"<<endl;
        exit(-1);
    }
     

    proof = EdVRF_Prove(SK, M, true, false); // yes elligator2
    if(proof!=proofElligator2_value) {
        cout<<endl<<"ERROR: ProofElligator2 = ";
        cout<<proof;
        cout<<endl;
        exit(-1);
    }
    if(!EdVRF_Verify(proof, PK, M, true)) {
        cout<<endl<<"ERROR: Verification yes Elligator2"<<endl;
        exit(-1);
    }
}

void testOrder8Points() {
    // These are from Section 5.6.1 of vrf draft
    ZZ bad_y2 = conv<ZZ> ("2707385501144840649318225287225658788936804267575313519463743609750303402022");
    str bad_pk [] = {
        str(ZZ(0), 32),
        str(ZZ(1), 32),
        str(bad_y2, 32),
        str(p-bad_y2, 32),
        str(p-1, 32),
        str(p, 32),
        str(p+1, 32)};
    
    ZZ_p bad_y2_p = conv<ZZ_p>(bad_y2);
    
    // these are from https://cr.yp.to/ecdh.html#validate
    if(conv<ZZ>((1+bad_y2_p)/(1-bad_y2_p)) != conv<ZZ>("39382357235489614581723060781553021112529911719440698176882885853963445705823")) {
        cout << "ERROR: Montogmery and Edwards coordinates do not correspond" << endl;
    }
       
       if(conv<ZZ>((1-bad_y2_p)/(1+bad_y2_p)) != conv<ZZ>("325606250916557431795983626356110631294008115727848805560023387167927233504")) {
        cout << "ERROR: Montogmery and Edwards coordinates do not correspond" << endl;
    }

    for (int i =0; i<7; i++) {
        bool isValid;
        pointEd25519 pt =bad_pk[i].toECPoint(isValid);
        if (!isValid) {
            cout << "ERROR: point " << i <<"  is not even a valid point!\n";
        }
        bool success = false;
        for (ZZ j(1); j<16; j*=2) {
            if (((bad_pk[i].toECPoint(isValid))*j).isInfinity()) {
                cout << "Point " << i <<"  has order "<< j << ".\n";
                success = true;
                break;
            }
        }
        if (not success)
            cout << "ERROR: point " << i <<"  is not bad!\n";

    }
}

bool testElligator2Example (const char * M_input, const char * u, const char * x, const char * y) {
    ZZ_p u_res = Elligator2_hash_to_field(str::fromCString(M_input), ELLIGATOR2_TEST_DST, false);
    if (conv<ZZ>(u_res) != str(u).toZZ_bigEndian()) {
        cout << "ERROR Elligator2_hash_to_field on example \"" << M_input << "\"" << endl;
        return false;
    }
    else {
        pointEd25519 output = Elligator2_map_to_curve_and_clear_cofactor(u_res, false);
        if (conv<ZZ>(output.x) != str(x).toZZ_bigEndian() || conv<ZZ>(output.y) != str(y).toZZ_bigEndian()) {
            cout << "ERROR Elligator2_map_to_curve_and_clear_cofactor on example \"" << M_input << "\"" << endl;
            return false;
        }
    }
    return true;
}

void testElligator2() {
    /* These test vectors are from CFRG hash-to-curve draft https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve/blob/8ec5a3fdcbfc05d00ab18aa419ddfc895cb5b686/draft-irtf-cfrg-hash-to-curve.md#edwards25519_xmdsha-256_ell2_nu_ */
    /* Note that they are big-endian, unlike other test vectors in this code */
    testElligator2Example("",
                         "155c21d4cd09704fb445dbd195567689dfee8746f6a41a8e2dd344f370635fdc",
                         "6252360003d43811610d39f67f0a479c4c52f8bc515e7ce6907b5894ea040835",
                         "4af6284e3cc7116df104f6708e0c44d79b0e294ccd89b87c4c3c892ebd2f03b1");
    testElligator2Example("abc",
                         "44affc91a5e431c6bba08db58d4155bc73ab1369871efe48457fb879873edebe",
                         "5cdeb5456820bd6f73e4d077b4bfba83a7dc50e875144467b7dd2041e5e2bcc3",
                         "23e704500ac22fd7106ceedd86bfcc8d50351a6303be22b2724fcc1280d00544");
    testElligator2Example("abcdef0123456789",
                         "397af6c051fae69ac233a8f147d73d5ad5524164f8ab02081c0563b035e23fe3",
                         "38dc8f399cd639b444bf4d5a58084874f4ae4d393aa07d9fda73f865e636bac6",
                         "34b8a16b923101f2d4caa48d9bb86fef4f92be0ce0f55c8ba9db55da23ad623e");
   testElligator2Example("a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "1468be7f7907b634683fd7f5d7dbc71603eca5cc4643a6e760902c0bffb994c0",
                        "110d8143f8ed73bbb2f9a85de1abd2718cb4bb7db006296883ed6c8524518a67",
                        "31e648bbade3b272b7676f82da905d27de37f41581b1d170250dd9d56f95413c"
                     );

}


void test() {
    // Examples are from https://tools.ietf.org/html/rfc8032#section-7.1; vrf values are our own
    
    testEdDSAExample("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                     "",
                     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",  "8657106690b5526245a92b003bb079ccd1a92130477671f6fc01ad16f26f723f26f8a57ccaed74ee1b190bed1f479d9727d2d0f9b005a6e456a35d4fb0daab1268a1b0db10836d9826a528ca76567805", "7d9c633ffeee27349264cf5c667579fc583b4bda63ab71d001f89c10003ab46f14adf9a3cd8b8412d9038531e865c341cafa73589b023d14311c331a9ad15ff2fb37831e00f0acaa6d73bc9997b06501");
    testEdDSAExample("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                     "72",
                     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",  "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",  "f3141cd382dc42909d19ec5110469e4feae18300e94f304590abdced48aed5933bf0864a62558b3ed7f2fea45c92a465301b3bbf5e3e54ddf2d935be3b67926da3ef39226bbc355bdc9850112c8f4b02", "47b327393ff2dd81336f8a2ef10339112401253b3c714eeda879f12c509072ef055b48372bb82efbdce8e10c8cb9a2f9d60e93908f93df1623ad78a86a028d6bc064dbfc75a6a57379ef855dc6733801");
    
    testEdDSAExample("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                     "af82",
                     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",  "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",  "9bc0f79119cc5604bf02d23b4caede71393cedfbb191434dd016d30177ccbf8096bb474e53895c362d8628ee9f9ea3c0e52c7a5c691b6c18c9979866568add7a2d41b00b05081ed0f58ee5e31b3a970e",                     "926e895d308f5e328e7aa159c06eddbe56d06846abf5d98c2512235eaa57fdce35b46edfc655bc828d44ad09d1150f31374e7ef73027e14760d42e77341fe05467bb286cc2c9d7fde29120a0b2320d04");
}

void generateVectors() {
    cout<<"    <section numbered=\"true\" toc=\"default\">" << endl;
    cout<<"        <name>ECVRF-EDWARDS25519-SHA512-TAI</name>"  << endl << endl;
    cout<<"        <t>The example secret keys and messages in Examples 7, 8, and 9 are taken from Section 7.1 of <xref target=\"RFC8032\" format=\"default\"/>.</t>" << endl;

    cout<<endl<<"        <t>Example 7:</t>"<<endl;
    generateTestVector("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                       "", false);

    cout<<endl<<"        <t>Example 8:</t>"<<endl;
    generateTestVector("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                     "72", false);

    cout<<endl<<"        <t>Example 9:</t>"<<endl;
    generateTestVector("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                       "af82",false);
    cout<<"      </section>"<<endl;
    
    cout<<endl<<"      <section numbered=\"true\" toc=\"default\">" << endl;
    cout<<"        <name>ECVRF-EDWARDS25519-SHA512-ELL2</name>"  << endl << endl;
    cout<<"        <t>The example secret keys and messages in Examples 10, 11, and 12 are taken from Section 7.1 of <xref target=\"RFC8032\" format=\"default\"/>.</t>" << endl;

    cout<<endl<<"        <t>Example 10:</t>"<<endl;
    generateTestVector("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                     "", true);

    cout<<endl<<"        <t>Example 11:</t>"<<endl;
    generateTestVector("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                     "72", true);

    cout<<endl<<"        <t>Example 12:</t>"<<endl;
    generateTestVector("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                       "af82",true);
    cout<<"      </section>"<<endl;
}

void generateRandomElligator2TestVector() {
    // A random sk
    char sk_string[65];
    sk_string[64]='\0';
    for(int i=0; i<8; i++) {
        sprintf(sk_string+8*i, "%08x", rand());
    }
    
    // a random message of length 0--49 bytes
    int len = rand()%50;
    char * m_string = new char[2*len+1];
    m_string[2*len]='\0';
    for(int i=0; i<len; i++) {
        sprintf(m_string+2*i, "%02x", rand()%256);
    }
    

    str SK(sk_string);
    cout << SK << endl;
    str M(m_string);
    cout << M.len << " " << M << endl;
    cout << EdVRF_Prove(SK, M, true, false) << endl << endl;
    
/*    cout << "SK = " EdDSA_KeyGen(str(sk_string))<<endl;
    cout<< len << " " << m_string<<endl;
    EdVRF_Prove(str(sk_string), str(m_string), true, true);
    cout << endl;*/
    delete [] m_string;
}


int main()
{
    
    initialize();
    testElligator2();
    testOrder8Points();
    test();
    generateVectors();
   
    //srand(5);
    //for (int i = 0; i<1000; i++) generateRandomElligator2TestVector();
}
