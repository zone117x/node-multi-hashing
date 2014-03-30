#include <node.h>
#include <node_buffer.h>
#include <v8.h>

extern "C" {
    #include "bcrypt.h"
    #include "keccak.h"
    #include "quark.h"
    #include "scrypt.h"
    #include "scryptjane.h"
    #include "scryptn.h"
    #include "skein.h"
    #include "x11.h"


    static unsigned char getNfactor(char* blockheader) {
        int n,l = 0;
        unsigned long nTimestamp = *(unsigned int*)(&blockheader[68]);
        unsigned char minNfactor = 10;
        unsigned char maxNfactor = 30;
        unsigned char N;
        uint64_t s;

        if (nTimestamp <= 1389306217) {
            return minNfactor;
        }

        s = nTimestamp - 1389306217;
        while ((s >> 1) > 3) {
          l += 1;
          s >>= 1;
        }

        s &= 3;

        n = (l * 158 + s * 28 - 2670) / 100;

        if (n < 0) n = 0;

        N = (unsigned char) n;
        n = N > minNfactor ? N : minNfactor;
        N = n < maxNfactor ? n : maxNfactor;

        return N;
    }

    #define max(a,b)            (((a) > (b)) ? (a) : (b))
    #define min(a,b)            (((a) < (b)) ? (a) : (b))
    unsigned char GetNfactorJane(int nTimestamp, int nChainStartTime) {

            const unsigned char minNfactor = 4;
            const unsigned char maxNfactor = 30;

            int l = 0, s, n;
            unsigned char N;

            if (nTimestamp <= nChainStartTime)
                    return 4;

            s = nTimestamp - nChainStartTime;
            while ((s >> 1) > 3) {
                    l += 1;
                    s >>= 1;
            }

            s &= 3;

            n = (l * 170 + s * 25 - 2320) / 100;

            if (n < 0) n = 0;

            if (n > 255)
                    printf("GetNfactor(%d) - something wrong(n == %d)\n", nTimestamp, n);

            N = (unsigned char)n;
            //printf("GetNfactor: %d -> %d %d : %d / %d\n", nTimestamp - nChainStartTime, l, s, n, min(max(N, minNfactor), maxNfactor));

            return min(max(N, minNfactor), maxNfactor);
    }

    void scryptjane_hash(const void* input, size_t inputlen, uint32_t *res, unsigned char Nfactor)
    {
            return scrypt((const unsigned char*)input, inputlen,
                    (const unsigned char*)input, inputlen,
                    Nfactor, 0, 0, (unsigned char*)res, 32);
    }
}

using namespace node;
using namespace v8;

Handle<Value> except(const char* msg) {
    return ThrowException(Exception::Error(String::New(msg)));
}

Handle<Value> quark(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char * output = new char[32];

    quark_hash(input, output);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}

Handle<Value> x11(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char * output = new char[32];

    x11_hash(input, output);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}

Handle<Value> scrypt(const Arguments& args) {
   HandleScope scope;

   if (args.Length() < 1)
       return except("You must provide one argument.");

   Local<Object> target = args[0]->ToObject();

   if(!Buffer::HasInstance(target))
       return except("Argument should be a buffer object.");

   char * input = Buffer::Data(target);
   char * output = new char[32];

   scrypt_1024_1_1_256(input, output);

   Buffer* buff = Buffer::New(output, 32);
   return scope.Close(buff->handle_);
}



Handle<Value> scryptn(const Arguments& args) {
   HandleScope scope;

   if (args.Length() < 1)
       return except("You must provide one argument.");

   Local<Object> target = args[0]->ToObject();

   if(!Buffer::HasInstance(target))
       return except("Argument should be a buffer object.");



   char * input = Buffer::Data(target);
   char * output = new char[32];

   unsigned int N = 1 << (getNfactor(input) + 1);

   scrypt_N_1_1_256(input, output, N);

   Buffer* buff = Buffer::New(output, 32);
   return scope.Close(buff->handle_);
}

Handle<Value> scryptjane(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 3)
        return except("You must provide two argument: buffer, timestamp as number, and nChainStarTime as number");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("First should be a buffer object.");

    Local<Number> num = args[1]->ToNumber();
    int timestamp = num->Value();

    Local<Number> num2 = args[2]->ToNumber();
    int nChainStarTime = num2->Value();


    char * input = Buffer::Data(target);
    char * output = new char[32];

    scryptjane_hash(input, 80, (uint32_t *)output, GetNfactorJane(timestamp, nChainStarTime));

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}

Handle<Value> keccak(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char * output = new char[32];

    keccak_hash(input, output);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}


Handle<Value> bcrypt(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char * output = new char[32];

    bcrypt_hash(input, output);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}

void init(Handle<Object> exports) {
    exports->Set(String::NewSymbol("quark"), FunctionTemplate::New(quark)->GetFunction());
    exports->Set(String::NewSymbol("x11"), FunctionTemplate::New(x11)->GetFunction());
    exports->Set(String::NewSymbol("scrypt"), FunctionTemplate::New(scrypt)->GetFunction());
    exports->Set(String::NewSymbol("scryptn"), FunctionTemplate::New(scryptn)->GetFunction());
    exports->Set(String::NewSymbol("scryptjane"), FunctionTemplate::New(scryptjane)->GetFunction());
    exports->Set(String::NewSymbol("keccak"), FunctionTemplate::New(keccak)->GetFunction());
    exports->Set(String::NewSymbol("bcrypt"), FunctionTemplate::New(keccak)->GetFunction());
}

NODE_MODULE(multihashing, init)
