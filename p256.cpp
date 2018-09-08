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
#include "sha256.h"

NTL_CLIENT

static ZZ p, q;
static ZZ_p a, b, c;

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
    
    // from a big int
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
    
    // to hex string -- lowercase
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
    c = -b/a;

    q = conv<ZZ>( "115792089210356248762697446949407573529996955224135760342422259061068512044369");
    B = pointP256(conv<ZZ_p>("48439561293906451759052585252797914202762949526041747995844080717082404635286"), conv<ZZ_p>("36134250956749795798585127919587881956611106672985015071877198253568414405109"));
}

ZZ Nonce_Generation(const str & sk_string, const str & h_string) {
    str reduced_h_string = str((h_string.toZZ() % q), 32);
    str V(0x01, 32);
    str K(0x00, 32);
    str zero_string = str((unsigned char)0x00);
    str one_string = str((unsigned char)0x01);
    K = (V || zero_string || sk_string || reduced_h_string).HMAC(K);
    V = V.HMAC(K);
    K = (V || one_string || sk_string || reduced_h_string).HMAC(K);
    V = V.HMAC(K);
    ZZ ret;
    while(true) {
        V = V.HMAC(K);
        ret = V.toZZ();
        if (ret>0 && ret<q) return ret;
        K = (V || str(zero_string)).HMAC(K);
        V = V.HMAC(K);
    }
}

str ECDSA_Sign(const str & SK, const str & M) {
    // From https://tools.ietf.org/html/rfc6979#section-2.4
    str h_string = M.hash();
    ZZ k = Nonce_Generation(SK, h_string);
    ZZ r =  conv<ZZ>((B*k).x) % q;
    ZZ s;
    {
        // change the modulus to q
        ZZ_pPush push(q);
        ZZ_p smod = ((conv<ZZ_p>(h_string.toZZ())+conv<ZZ_p>(SK.toZZ())*conv<ZZ_p>(r)))/conv<ZZ_p>(k);
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
    unsigned char one_string = 0x01;
    unsigned char two_string = 0x02;
    unsigned char suite_string = 0x01;
    for (;; ctr++) {
        str h_string = str(two_string) || (str(suite_string) || str(one_string) || pk_string || alpha_string || str(ctr, 1)).hash();

        bool isValid;
        pointP256 H = h_string.toECPoint(isValid);
        if (isValid) {
            if (verbose) cout << "try_and_increment succeded on ctr = " << ctr << " <vspace />" << endl;
            return H;
        }
    }
}


pointP256 SWU(const str & pk_string, const str & alpha_string, bool verbose) {
    unsigned char one_string = 0x01;
    unsigned char suite_string = 0x02;
    unsigned char two_string = 0x02;


    str hash_string = (str(suite_string) || str(one_string) || pk_string || alpha_string).hash();
    ZZ t_int = hash_string.toZZ();
    ZZ_p t = conv<ZZ_p>(t_int);
    if (verbose) cout << "In SWU: t = " << str(conv<ZZ>(t), 32) << " <vspace />" << endl;

    ZZ_p r = -(t*t);
    ZZ_p d = r*r+r;
    ZZ_p d_inverse = IsZero(d) ? d : inv(d); // same as power(d, p-2);
    ZZ_p x = c*(1+d_inverse);
    ZZ_p w = x*x*x+a*x+b;
    if (verbose) cout << "In SWU: w = " << str(conv<ZZ>(w), 32) << " <vspace />" << endl;
    int jacobi = Jacobi(conv<ZZ>(w), p);
    if (verbose) cout << "In SWU: e = " << jacobi << " <vspace />" << endl;

    if (jacobi == -1) {
        x *= r;
    }
    bool isValid;
    pointP256 H = (str(two_string) || str(conv<ZZ>(x), 32)).toECPoint(isValid);
    if (!isValid) {
        cout<<"SWU error"<<endl;
        exit(-1);
    }
    return H;
}

ZZ ECVRF_Hash_Points(const pointP256 & p1, const pointP256 & p2, const pointP256 & p3, const pointP256 & p4, unsigned char suite_string) {
    unsigned char two_string = 0x02;

    return (str(suite_string) || str(two_string) || str(p1) || str(p2) || str(p3) || str(p4)).hash().slice(0,16).toZZ();
}


str ECVRF_Prove(const str & SK, const str & alpha_string, bool useSWU, bool verbose) {
    // Secret Scalar
    ZZ x = SK.toZZ();
    // public key
    str PK(B*x);
    
    // hash to curve
    unsigned char suite_string = useSWU? 0x02 : 0x01;
    pointP256 H = useSWU ? SWU(PK, alpha_string, verbose) : Try_And_Increment(PK, alpha_string, verbose);
    
    if (verbose) cout << "H = " << str(H) << " <vspace />" << endl;

    
    pointP256 Gamma = H*x;
    ZZ k = Nonce_Generation(SK, str(H));
    if (verbose) cout << "k = " << str(k, 32) << " <vspace />" << endl;
    
    pointP256 U = B*k;
    pointP256 V = H*k;
    if (verbose) cout << "U = k*B = " << str(U) << " <vspace />" << endl;
    if (verbose) cout << "V = k*H = " << str(V) << " <vspace />" << endl;

    ZZ c = ECVRF_Hash_Points(H, Gamma, U, V, suite_string);
    ZZ s = (k+c*x) % q;

    str proof = str(Gamma) || str(c, 16) || str(s, 32);
    if (verbose) cout << "pi = " << proof << " <vspace />" << endl;
    
    // proof_to_hash
    unsigned char three_string = 0x03;
    if (verbose) cout << "beta = " << (str(suite_string) || str(three_string) || str(Gamma)).hash();

    return proof;
}

bool ECVRF_Verify(const str & proof, const str & PK, const str & alpha_string, bool useSWU) {
    unsigned char suite_string = useSWU? 0x02 : 0x01;
    
    // get the pk
    bool isValid;
    pointP256 Y = PK.toECPoint(isValid);
    if (!isValid) return false;
    
    // parse the proof
    pointP256 Gamma = proof.slice(0, 33).toECPoint(isValid);
    ZZ c = proof.slice(33, 49).toZZ();
    ZZ s = proof.slice(49, 81).toZZ();

    // Hash to curve
    pointP256 H = useSWU ? SWU(PK, alpha_string, false) : Try_And_Increment(PK, alpha_string, false);

    // Hash points
    ZZ cprime = ECVRF_Hash_Points(H, Gamma, B*s-Y*c, H*s-Gamma*c, suite_string);
    
    return c==cprime;
    
}

void generateTestVector(const char * sk_input, const char * M_input, bool useSWU) {
    str SK(sk_input);
    cout<<"<t>"<<endl;
    cout << "SK = x = " << str(SK) << " <vspace />" << endl;
    cout << "PK = " << B*SK.toZZ() << " <vspace />" << endl;
    str M(M_input);
    cout << "alpha = " << M << " (ASCII \"";
    for (int i=0; i<M.len; i++) cout<< M.s[i];
    cout <<"\") <vspace />" << endl;
    str proof = ECVRF_Prove(SK, str(M_input), useSWU, true);
    cout<<"</t>"<<endl;
}

void testECDSAExample (const char * sk_input, const char* M_input, const char * pk_value,  const char* sig_value,const char* proofNoSWU_value, const char* proofSWU_value) {
   
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
    
    str M(M_input);

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
    str proof = ECVRF_Prove(SK, M, false, false); // no SWU
    if(proof!=proofNoSWU_value) {
        cout<<endl<<"ERROR: ProofNoSWU = ";
        cout<<proof;
        cout<<endl;
        exit(-1);
    }
    if(!ECVRF_Verify(proof, PK, M, false)) {
        cout<<endl<<"ERROR: Verification no SWU"<<endl;
        exit(-1);
    }
     

    proof = ECVRF_Prove(SK, M, true, false); // yes SWU
    if(proof!=proofSWU_value) {
        cout<<endl<<"ERROR: ProofSWU = ";
        cout<<proof;
        cout<<endl;
        exit(-1);
    }
    if(!ECVRF_Verify(proof, PK, M, true)) {
        cout<<endl<<"ERROR: Verification yes SWU"<<endl;
        exit(-1);
    }
    
}

void test () {
    // Examples are from https://tools.ietf.org/html/rfc6979#appendix-A.2.5; vrf values are our own
    
    testECDSAExample("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
                     "73616D706C65", // ascii "sample"
                     "0360FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6",
                     //"882905F1227FD620FBF2ABF21244F0BA83D0DC3A9103DBBEE43A1FB858109DB4",
                     "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8",
                     "029BDCA4CC39E57D97E2F42F88BCF0ECB1120FB67EB408A856050DBFBCBF57C524193B7A850195EF3D5329018A8683114CB446C33FE16EBCC0BC775B043B5860DCB2E553D91268281688438DF9394103AB",
                     "021D684D682E61DD76C794EEF43988A2C61FBDB2AF64FBB4F435CC2A842B0024C35641FE838A72D0D9BC1BCF032F895F3B3F4C79D0F8F9D5705D83181FE82E19F49619EB8290930809B2B9651786E4F945");
    testECDSAExample("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
                     "74657374", // ascii "test"
                     "0360FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6",
                     //"882905F1227FD620FBF2ABF21244F0BA83D0DC3A9103DBBEE43A1FB858109DB4",
                     "F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083",
                     "03873A1CCE2CA197E466CC116BCA7B1156FFF599BE67EA40B17256C4F34BA2549C9C8B100049E76661DBCF6393E4D625597ED21D4DE684E08DC6817B60938F3FF4148823EA46A47FA8A4D43F5FA6F77DC8",
                     "0376B758F457D2CABDFAEB18700E46E64F073EB98C119DEE4DB6C5BB1EAF677806895AB451335F6ADB792D40C68351929FCE44068FFDCBBEAC12F058B0365856ED5D86AADBA1F54C9DB13F9C8759589609");
    
    // This example is from ANSI X9.62 2005 L.4.2
    ZZ ANSIX962sk =  conv<ZZ>("20186677036482506117540275567393538695075300175221296989956723148347484984008");
    str ANSIX962SK(ANSIX962sk, 32);
    
    
    testECDSAExample (ANSIX962SK.toHexString(),
                      "4578616D706C65206F66204543445341207769746820616E736970323536723120616E64205348412D323536", // ascii "Example of ECDSA with ansix9p256r1 and SHA-256"
                      "03596375E6CE57E0F20294FC46BDFCFD19A39F8161B58695B3EC5B3D16427C274D",
                      NULL,
                      "02abe3ce3b3aa2ab3c6855a7e729517ebfab6901c2fd228f6fa066f15ebc9b9d41fd212750d9ff775527943049053a77252e9fa59e332a2e5d5db6d0be734076e98befcdefdcbaf817a5c13d4e45fbf9bc",
                      "035e844533a7c5109ab3dffd04f2ef0d38d679101124f15243199ce92f0f29477cd29f8754f3bbdea3dd129560e9ba0c73ae7894a8d0c0e1ac01e5c2685da67009d96e6ccdb634c7e0c5f38fa3e4908c02"
                      );
    
}


void generateVectors() {
    // This example is from ANSI X9.62 2005 L.4.2
    ZZ ANSIX962sk =  conv<ZZ>("20186677036482506117540275567393538695075300175221296989956723148347484984008");
    str ANSIX962SK(ANSIX962sk, 32);

  
    cout<<"<section title=\"ECVRF-P256-SHA256-TAI\">"<<endl;
    cout<<"<t>These two example secret keys and messages are taken from Appendix A.2.5 of <xref target=\"RFC6979\"/>.</t>"<<endl;
    generateTestVector("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
                       "73616D706C65", false);
    generateTestVector("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
                       "74657374", false);
    
    cout<<"<t>This example secret key and message are taken from Appendix L.4.2 of <xref target=\"ANSI.X9-62-2005\"/>.</t>"<<endl;

    generateTestVector(ANSIX962SK.toHexString(),
                       "4578616D706C65206F66204543445341207769746820616E736970323536723120616E64205348412D323536", false);

    cout<<"</section>"<<endl;
    cout<<"<section title=\"ECVRF-P256-SHA256-SWU\">"<<endl;
    cout<<"<t>These two example secret keys and messages are taken from Appendix A.2.5 of <xref target=\"RFC6979\"/>.</t>"<<endl;
    
    generateTestVector("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
                       "73616D706C65", true);
    generateTestVector("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
                       "74657374", true);
    
    cout<<"<t>This example secret key and message are taken from Appendix L.4.2 of <xref target=\"ANSI.X9-62-2005\"/>.</t>"<<endl;
    generateTestVector(ANSIX962SK.toHexString(),
                       "4578616D706C65206F66204543445341207769746820616E736970323536723120616E64205348412D323536", true);
    cout<<"</section>"<<endl;

}

int main()
{
    
    initialize();
    test();
    generateVectors();
    
}
