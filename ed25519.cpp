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
 IT IS ALSO INEFFICIENT AND COBBLED TOGETHER IN ONE DAY!!! DO NOT USE IT!!
 It was written by Leo Reyzin as a reference implementation only, in order to generate test vectors.
 */


#include <NTL/ZZ_pXFactoring.h>
#include <NTL/ZZXFactoring.h>
#include "sha512.h"

NTL_CLIENT

static ZZ p, q, cofactor;
static ZZ_p A, d;

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
     birationally equivalent to montgomery: u, v v2 = u(u2 + Au + 1) (in Mongomery, we store only u as PK).
     Conversion x=(u/v) * \sqrt(-486664),y=(u-1)/(u+1)
     To go back: u = (1+y)/(1-y) whenever (x, y) is not the point at infinity).
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
    
    // from an EC point
    str(const pointEd25519 & p) {
        len = 32;
        s = new unsigned char[len];
        p.toBytes(s);
    }
    
    // from a big int
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
    
    // to int
    ZZ toZZ() const {
        ZZ ret;
        ZZFromBytes(ret, s, len);
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



void initialize() {
    power2(p, 255);
    p-=19;
    ZZ_p::init(p);
    
    d=ZZ_p(-121665)/ZZ_p(121666);
    
    A = ZZ_p(486662);
    
    cofactor = ZZ(8);
    
    B = pointEd25519(conv<ZZ_p>("15112221349535400772501151409588531511454012693041857206046113283949847762202"), conv<ZZ_p>("46316835694926478169428394003475163141307993866256225615783033603165251855960"));
    
    power2(q, 252);
    q+=conv<ZZ>("27742317777372353535851937790883648493");
}

pointEd25519 Try_And_Increment(const str & pk_string, const str & alpha_string, bool verbose) {
    ZZ ctr(0);
    unsigned char one_string = 0x01;
    unsigned char suite_string = 0x03;
    for (;; ctr++) {
        str h_string = (str(suite_string) || str(one_string) || pk_string || alpha_string || str(ctr, 1)).hash();

        pointEd25519 * H = pointEd25519::string_to_point(h_string.s);
        if (H!=NULL) {
            pointEd25519 G = (*H)*cofactor;
            if (!G.isInfinity()) {
                delete H;
                if (verbose) cout << "try_and_increment succeded on ctr = " << ctr << " <vspace />" << endl;
                return G;
            }
            delete H;
        }
    }
}


pointEd25519 Elligator2(const str & pk_string, const str & alpha_string, bool verbose) {
    unsigned char one_string = 0x01;
    unsigned char suite_string = 0x04;

    str hash_string = (str(suite_string) || str(one_string) || pk_string || alpha_string).hash();

    unsigned char x0 = hash_string.s[31] & 0x80;
    hash_string.s[31] &= 0x7F;
    ZZ r_int = hash_string.slice(0, 32).toZZ();
    ZZ_p r = conv<ZZ_p>(r_int);
    if (verbose) cout << "In Elligator: r = " << str(r_int, 32) << " <vspace />" << endl;

    
    ZZ_p u = - A / (1 + 2*r*r );
    ZZ_p w = u * (u*u + A*u + 1);
    if (verbose) cout << "In Elligator: w = " << str(conv<ZZ>(w), 32) << " <vspace />" << endl;
    if (Jacobi(conv<ZZ>(w), p) != 1) {
        if (verbose) cout << "In Elligator: e = -1" << " <vspace />" << endl;
        u = -A-u;
    }
    else if (verbose) cout << "In Elligator: e = 1" << " <vspace />" << endl;
    ZZ_p y = (u-1)/(u+1);
    
    str H_string(conv<ZZ>(y), 32);
    //H_string.s[31]|=x0;
    bool isValid;
    pointEd25519 H = H_string.toECPoint(isValid);
    if (!isValid) {
        cout<<"Elligator error"<<endl;
        exit(-1);
    }
    return H*cofactor;
}

ZZ EdVRF_Hash_Points(const pointEd25519 & p1, const pointEd25519 & p2, const pointEd25519 & p3, const pointEd25519 & p4, unsigned char suite_string) {
    unsigned char two_string = 0x02;

    return (str(suite_string) || str(two_string) || str(p1) || str(p2) || str(p3) || str(p4)).hash().slice(0,16).toZZ();
}

str EdVRF_Prove(const str & SK, const str & alpha_string, bool useElligator, bool verbose) {
    // From https://tools.ietf.org/html/rfc8032#section-5.1.5
    
    str h = SK.hash();
        
    h.s[0]&=0xF8;
    h.s[31]&=0x7F;
    h.s[31]|=0x40;

    // secret scalar
    ZZ x = h.slice(0, 32).toZZ();
    
    if (verbose) cout << "x = " << str(x, 32) << " <vspace />" << endl;

    
    // public key
    str PK(B*x);

    // hash to curve
    unsigned char suite_string = useElligator? 0x04 : 0x03;
    pointEd25519 H = useElligator ? Elligator2(PK, alpha_string, verbose) : Try_And_Increment(PK, alpha_string, verbose);
    
    if (verbose) cout << "H = " << str(H) << " <vspace />" << endl;

    pointEd25519 Gamma = H*x;

    // Nonce Generation
    str k_string = (h.slice(32,64) || str(H)).hash();
    ZZ k = k_string.toZZ();
    if (verbose) cout << "k = " << str(k, 64) << " <vspace />" << endl;

    // Hash points
    pointEd25519 U = B*k;
    pointEd25519 V = H*k;
    if (verbose) cout << "U = k*B = " << str(U) << " <vspace />" << endl;
    if (verbose) cout << "V = k*H = " << str(V) << " <vspace />" << endl;

    ZZ c = EdVRF_Hash_Points(H, Gamma, U, V, suite_string);
    
    ZZ s = (k+c*x) % q;
    
    str proof = str(Gamma) || str(c, 16) || str(s, 32);
    if (verbose) cout << "pi = " << proof << " <vspace />" << endl;
    
    // proof_to_hash
    unsigned char three_string = 0x03;
    if (verbose) cout << "beta = " << (str(suite_string) || str(three_string) || str(Gamma*cofactor)).hash();
    
    return proof;
}

bool EdVRF_Verify(const str & proof, const str & PK, const str & alpha_string, bool useElligator) {
    unsigned char suite_string = useElligator? 0x04 : 0x03;
    
    // get the pk
    bool isValid;
    pointEd25519 Y = PK.toECPoint(isValid);
    if (!isValid) return false;
    
    // parse the proof
    pointEd25519 Gamma = proof.slice(0, 32).toECPoint(isValid);
    if (!isValid) return false;
    ZZ c = proof.slice(32, 48).toZZ();
    ZZ s = proof.slice(48, 80).toZZ();

    // Hash to curve
    pointEd25519 H = useElligator ? Elligator2(PK, alpha_string, false) : Try_And_Increment(PK, alpha_string, false);

    // Hash points
    ZZ cprime = EdVRF_Hash_Points(H, Gamma, B*s-Y*c, H*s-Gamma*c, suite_string);
    
    return c==cprime;
    
}

void generateTestVector(const char * sk_input, const char * M_input, bool useElligator) {
    str SK(sk_input);
    cout<<"<t>"<<endl;
    cout << "SK = " << str(SK) << " <vspace />" << endl;
    cout << "PK = " << EdDSA_KeyGen(SK) << " <vspace />" << endl;
    str M(M_input);
    cout << "alpha = " << M ;
    if(M.len == 0) cout << " (the empty string)";
    else if(M.len == 1) cout << " (1 byte)";
    else cout << " (" << M.len << " bytes)";
    cout <<" <vspace />" << endl;
    str proof = EdVRF_Prove(SK, str(M_input), useElligator, true);
    cout<<"</t>"<<endl;
}

void testEdDSAExample (const char * sk_input,  const char* M_input, const char * pk_value, const char* sig_value, const char* proofNoElligator_value, const char* proofElligator_value) {
   
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
    str proof = EdVRF_Prove(SK, M, false, false); // no elligator
    if(proof!=proofNoElligator_value) {
        cout<<endl<<"ERROR: ProofNoElligator = ";
        cout<<proof;
        cout<<endl;
        exit(-1);
    }
    if(!EdVRF_Verify(proof, PK, M, false)) {
        cout<<endl<<"ERROR: Verification no Elligator"<<endl;
        exit(-1);
    }
     

    proof = EdVRF_Prove(SK, M, true, false); // yes elligator
    if(proof!=proofElligator_value) {
        cout<<endl<<"ERROR: ProofElligator = ";
        cout<<proof;
        cout<<endl;
        exit(-1);
    }
    if(!EdVRF_Verify(proof, PK, M, true)) {
        cout<<endl<<"ERROR: Verification yes Elligator"<<endl;
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
        if (!((bad_pk[i].toECPoint(isValid))*cofactor).isInfinity()) {
            cout << "ERROR: point " << i <<"  is not bad!\n";
        }
    }
}



void test() {
    // Examples are from https://tools.ietf.org/html/rfc8032#section-7.1; vrf values are our own
    
    testEdDSAExample("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                     "",
                     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",  "9275df67a68c8745c0ff97b48201ee6db447f7c93b23ae24cdc2400f52fdb08a1a6ac7ec71bf9c9c76e96ee4675ebff60625af28718501047bfd87b810c2d2139b73c23bd69de66360953a642c2a330a", "b6b4699f87d56126c9117a7da55bd0085246f4c56dbc95d20172612e9d38e8d7ca65e573a126ed88d4e30a46f80a666854d675cf3ba81de0de043c3774f061560f55edc256a787afe701677c0f602900");
    testEdDSAExample("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                     "72",
                     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",  "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",  "84a63e74eca8fdd64e9972dcda1c6f33d03ce3cd4d333fd6cc789db12b5a7b9d03f1cb6b2bf7cd81a2a20bacf6e1c04e59f2fa16d9119c73a45a97194b504fb9a5c8cf37f6da85e03368d6882e511008", "ae5b66bdf04b4c010bfe32b2fc126ead2107b697634f6f7337b9bff8785ee111200095ece87dde4dbe87343f6df3b107d91798c8a7eb1245d3bb9c5aafb093358c13e6ae1111a55717e895fd15f99f07");
    
    testEdDSAExample("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                     "af82",
                     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",  "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",  "aca8ade9b7f03e2b149637629f95654c94fc9053c225ec21e5838f193af2b727b84ad849b0039ad38b41513fe5a66cdd2367737a84b488d62486bd2fb110b4801a46bfca770af98e059158ac563b690f",                     "dfa2cba34b611cc8c833a6ea83b8eb1bb5e2ef2dd1b0c481bc42ff36ae7847f6ab52b976cfd5def172fa412defde270c8b8bdfbaae1c7ece17d9833b1bcf31064fff78ef493f820055b561ece45e1009");
}

void generateVectors() {
    cout<<"<section title=\"ECVRF-ED25519-SHA512-TAI\">"<<endl;
    cout<<"<t>These three example secret keys and messages are taken from Section 7.1 of <xref target=\"RFC8032\"/>.</t>"<<endl;
    generateTestVector("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                     "", false);
    generateTestVector("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                     "72", false);
    generateTestVector("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                       "af82",false);
    cout<<"</section>"<<endl;
    cout<<"<section title=\"ECVRF-ED25519-SHA512-Elligator2\">"<<endl;
    cout<<"<t>These three example secret keys and messages are taken from Section 7.1 of <xref target=\"RFC8032\"/>.</t>"<<endl;

    generateTestVector("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                     "", true);
    generateTestVector("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                     "72", true);
    generateTestVector("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                       "af82",true);
    cout<<"</section>"<<endl;
}

int main()
{
    
    initialize();
    testOrder8Points();
    test();
    generateVectors();
}
