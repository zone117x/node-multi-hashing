#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include "nan.h"

extern "C" {
    #include "bcrypt.h"
    #include "keccak.h"
    #include "quark.h"
      #include "scryptn.h"
    #include "skein.h"
    #include "x11.h"
    #include "groestl.h"
    #include "blake.h"
    #include "fugue.h"
    #include "qubit.h"
    #include "hefty1.h"
    #include "shavite3.h"
    #include "cryptonight.h"
    #include "x13.h"
    #include "nist5.h"
    #include "sha1.h",
    #include "x15.h"
	#include "fresh.h"
}

#include "boolberry.h"

using namespace node;
using namespace v8;



void except(const char* msg)
{
	Nan::ThrowError(Exception::Error(Nan::New<String>(msg).ToLocalChecked()));
}




NAN_METHOD(quark)
{
	Isolate* isolate = info.GetIsolate();
	HandleScope scope(isolate);

	if (info.Length() < 1)
	{
		except("You must provide one argument.");
	}
	else
	{
		Local<Object> target = info[0]->ToObject();
		if (!node::Buffer::HasInstance(target))
		{
			except("Argument should be a buffer object.");

		}
		else
		{
			char * input = Buffer::Data(target);
			char* output = (char*)malloc(32);

			uint32_t input_len = Buffer::Length(target);

			quark_hash(input, output, input_len);

			auto result = node::Buffer::New(isolate, output, 32).ToLocalChecked();

			info.GetReturnValue().Set(result);
		}
	}
	

}


NAN_METHOD(x11)
{
	Isolate* isolate = info.GetIsolate();
	HandleScope scope(isolate);
	if (info.Length() < 1)
	{
		except("You must provide one argument.");
	}
	else
	{
		Local<Object> target = info[0]->ToObject();
		if (!node::Buffer::HasInstance(target))
		{
			except("Argument should be a buffer object.");

		}
		else
		{
			char * input = Buffer::Data(target);
			char* output = (char*)malloc(32);

			uint32_t input_len = Buffer::Length(target);

			x11_hash(input, output, input_len);

			auto result = node::Buffer::New(isolate, output, 32).ToLocalChecked();

			info.GetReturnValue().Set(result);
		}
	}

}

NAN_METHOD(scryptHash)
{
	Isolate* isolate = info.GetIsolate();
	HandleScope scope(isolate);
	if (info.Length() < 3)
	{
		except("You must provide buffer to hash, N value, and R value");
	}
	else
	{
		Local<Object> target = info[0]->ToObject();
		if (!node::Buffer::HasInstance(target))
		{
			except("Argument should be a buffer object.");

		}
		else
		{
			Local<Number> numn = info[1]->ToNumber();
			unsigned int nValue = numn->Value();
			Local<Number> numr = info[2]->ToNumber();
			unsigned int rValue = numr->Value();

			char * input = Buffer::Data(target);
			char* output = (char*)malloc(32);

			uint32_t input_len = Buffer::Length(target);

			scrypt_N_R_1_256(input, output, nValue, rValue, input_len);

			auto result = node::Buffer::New(isolate, output, 32).ToLocalChecked();

			info.GetReturnValue().Set(result);
		}
	}

}


NAN_METHOD(scryptn)
{
	Isolate* isolate = info.GetIsolate();
	HandleScope scope(isolate);
	if (info.Length() < 2)
	{
		except("You must provide buffer to hash and N factor.");
	}
	else
	{
		Local<Object> target = info[0]->ToObject();
		if (!node::Buffer::HasInstance(target))
		{
			except("Argument should be a buffer object.");

		}
		else
		{
			Local<Number> num = info[1]->ToNumber();
			unsigned int nFactor = num->Value();


			char * input = Buffer::Data(target);
			char* output = (char*)malloc(32);

			uint32_t input_len = Buffer::Length(target);
			unsigned int N = 1 << nFactor;
			scrypt_N_R_1_256(input, output, N, 1, input_len); //hardcode for now to R=1 for now

			auto result = node::Buffer::New(isolate, output, 32).ToLocalChecked();

			info.GetReturnValue().Set(result);
		}
	}

}

/*
NAN_METHOD(scryptjane)
{
	Isolate* isolate = info.GetIsolate();
	HandleScope scope(isolate);
	if (info.Length() < 5)
	{
		except("You must provide two argument : buffer, timestamp as number, and nChainStarTime as number, nMin, and nMax");
	}
	else
	{
		Local<Object> target = info[0]->ToObject();
		if (!node::Buffer::HasInstance(target))
		{
			except("Argument should be a buffer object.");

		}
		else
		{
			Local<Number> num = info[1]->ToNumber();
			int timestamp = num->Value();

			Local<Number> num2 = info[2]->ToNumber();
			int nChainStartTime = num2->Value();

			Local<Number> num3 = info[3]->ToNumber();
			int nMin = num3->Value();

			Local<Number> num4 = info[4]->ToNumber();
			int nMax = num4->Value();


			char * input = Buffer::Data(target);
			char* output = (char*)malloc(32);

			uint32_t input_len = Buffer::Length(target);

			scryptjane_hash(input, input_len, (uint32_t *)output, GetNfactorJane(timestamp, nChainStartTime, nMin, nMax));

			auto result = node::Buffer::New(isolate, output, 32).ToLocalChecked();

			info.GetReturnValue().Set(result);
		}
	}

}

*/


NAN_METHOD(keccak)
{
	Isolate* isolate = info.GetIsolate();
	HandleScope scope(isolate);
	if (info.Length() < 1)
	{
		except("You must provide one argument.");
	}
	else
	{
		Local<Object> target = info[0]->ToObject();
		if (!node::Buffer::HasInstance(target))
		{
			except("Argument should be a buffer object.");

		}
		else
		{
			char * input = Buffer::Data(target);
			char* output = (char*)malloc(32);

			uint32_t input_len = Buffer::Length(target);

			keccak_hash(input, output, input_len);

			auto result = node::Buffer::New(isolate, output, 32).ToLocalChecked();

			info.GetReturnValue().Set(result);
		}
	}

}

NAN_METHOD(bcrypt)
{
	Isolate* isolate = info.GetIsolate();
	HandleScope scope(isolate);
	if (info.Length() < 1)
	{
		except("You must provide one argument.");
	}
	else
	{
		Local<Object> target = info[0]->ToObject();
		if (!node::Buffer::HasInstance(target))
		{
			except("Argument should be a buffer object.");

		}
		else
		{
			char * input = Buffer::Data(target);
			char* output = (char*)malloc(32);

			uint32_t input_len = Buffer::Length(target);

			bcrypt_hash(input, output);

			auto result = node::Buffer::New(isolate, output, 32).ToLocalChecked();

			info.GetReturnValue().Set(result);
		}
	}

}

NAN_METHOD(skein)
{
	Isolate* isolate = info.GetIsolate();
	HandleScope scope(isolate);
	if (info.Length() < 1)
	{
		except("You must provide one argument.");
	}
	else
	{
		Local<Object> target = info[0]->ToObject();
		if (!node::Buffer::HasInstance(target))
		{
			except("Argument should be a buffer object.");

		}
		else
		{
			char * input = Buffer::Data(target);
			char* output = (char*)malloc(32);

			uint32_t input_len = Buffer::Length(target);

			skein_hash(input, output,input_len);

			auto result = node::Buffer::New(isolate, output, 32).ToLocalChecked();

			info.GetReturnValue().Set(result);
		}
	}

}


NAN_METHOD(groestl)
{
	Isolate* isolate = info.GetIsolate();
	HandleScope scope(isolate);
	if (info.Length() < 1)
	{
		except("You must provide one argument.");
	}
	else
	{
		Local<Object> target = info[0]->ToObject();
		if (!node::Buffer::HasInstance(target))
		{
			except("Argument should be a buffer object.");

		}
		else
		{
			char * input = Buffer::Data(target);
			char* output = (char*)malloc(32);

			uint32_t input_len = Buffer::Length(target);

			groestl_hash(input, output, input_len);

			auto result = node::Buffer::New(isolate, output, 32).ToLocalChecked();

			info.GetReturnValue().Set(result);
		}
	}

}



NAN_METHOD(groestlmyriad)
{
	Isolate* isolate = info.GetIsolate();
	HandleScope scope(isolate);
	if (info.Length() < 1)
	{
		except("You must provide one argument.");
	}
	else
	{
		Local<Object> target = info[0]->ToObject();
		if (!node::Buffer::HasInstance(target))
		{
			except("Argument should be a buffer object.");

		}
		else
		{
			char * input = Buffer::Data(target);
			char* output = (char*)malloc(32);

			uint32_t input_len = Buffer::Length(target);

			groestlmyriad_hash(input, output, input_len);

			auto result = node::Buffer::New(isolate, output, 32).ToLocalChecked();

			info.GetReturnValue().Set(result);
		}
	}

}





NAN_METHOD(blake)
{
	Isolate* isolate = info.GetIsolate();
	HandleScope scope(isolate);
	if (info.Length() < 1)
	{
		except("You must provide one argument.");
	}
	else
	{
		Local<Object> target = info[0]->ToObject();
		if (!node::Buffer::HasInstance(target))
		{
			except("Argument should be a buffer object.");

		}
		else
		{
			char * input = Buffer::Data(target);
			char* output = (char*)malloc(32);

			uint32_t input_len = Buffer::Length(target);

			blake_hash(input, output, input_len);

			auto result = node::Buffer::New(isolate, output, 32).ToLocalChecked();

			info.GetReturnValue().Set(result);
		}
	}

}

NAN_METHOD(fugue)
{
	Isolate* isolate = info.GetIsolate();
	HandleScope scope(isolate);
	if (info.Length() < 1)
	{
		except("You must provide one argument.");
	}
	else
	{
		Local<Object> target = info[0]->ToObject();
		if (!node::Buffer::HasInstance(target))
		{
			except("Argument should be a buffer object.");

		}
		else
		{
			char * input = Buffer::Data(target);
			char* output = (char*)malloc(32);

			uint32_t input_len = Buffer::Length(target);

			fugue_hash(input, output, input_len);

			auto result = node::Buffer::New(isolate, output, 32).ToLocalChecked();

			info.GetReturnValue().Set(result);
		}
	}

}

NAN_METHOD(qubit)
{
	Isolate* isolate = info.GetIsolate();
	HandleScope scope(isolate);
	if (info.Length() < 1)
	{
		except("You must provide one argument.");
	}
	else
	{
		Local<Object> target = info[0]->ToObject();
		if (!node::Buffer::HasInstance(target))
		{
			except("Argument should be a buffer object.");

		}
		else
		{
			char * input = Buffer::Data(target);
			char* output = (char*)malloc(32);

			uint32_t input_len = Buffer::Length(target);

			qubit_hash(input, output, input_len);

			auto result = node::Buffer::New(isolate, output, 32).ToLocalChecked();

			info.GetReturnValue().Set(result);
		}
	}

}


NAN_METHOD(hefty1)
{
	Isolate* isolate = info.GetIsolate();
	HandleScope scope(isolate);
	if (info.Length() < 1)
	{
		except("You must provide one argument.");
	}
	else
	{
		Local<Object> target = info[0]->ToObject();
		if (!node::Buffer::HasInstance(target))
		{
			except("Argument should be a buffer object.");

		}
		else
		{
			char * input = Buffer::Data(target);
			char* output = (char*)malloc(32);

			uint32_t input_len = Buffer::Length(target);

			hefty1_hash(input, output, input_len);

			auto result = node::Buffer::New(isolate, output, 32).ToLocalChecked();

			info.GetReturnValue().Set(result);
		}
	}

}

NAN_METHOD(shavite3)
{
	Isolate* isolate = info.GetIsolate();
	HandleScope scope(isolate);
	if (info.Length() < 1)
	{
		except("You must provide one argument.");
	}
	else
	{
		Local<Object> target = info[0]->ToObject();
		if (!node::Buffer::HasInstance(target))
		{
			except("Argument should be a buffer object.");

		}
		else
		{
			char * input = Buffer::Data(target);
			char* output = (char*)malloc(32);

			uint32_t input_len = Buffer::Length(target);

			shavite3_hash(input, output, input_len);

			auto result = node::Buffer::New(isolate, output, 32).ToLocalChecked();

			info.GetReturnValue().Set(result);
		}
	}

}

NAN_METHOD(cryptonight)
{
	Isolate* isolate = info.GetIsolate();
	HandleScope scope(isolate);

	bool fast = false;
	if (info.Length() < 1)
	{
		except("You must provide one argument.");
	}
	else
	{
		Local<Object> target = info[0]->ToObject();
		if (!node::Buffer::HasInstance(target))
		{
			except("Argument should be a buffer object.");

		}
		else
		{
			if (info.Length() >= 2) {
				if (!info[1]->IsBoolean())
				{
					except("Argument 2 should be a boolean");
					return;
				}
					
				fast = info[1]->ToBoolean()->BooleanValue();
			}

			char * input = Buffer::Data(target);
			char* output = (char*)malloc(32);

			uint32_t input_len = Buffer::Length(target);

			if (fast)
				cryptonight_fast_hash(input, output, input_len);
			else
				cryptonight_hash(input, output, input_len);

			auto result = node::Buffer::New(isolate, output, 32).ToLocalChecked();

			info.GetReturnValue().Set(result);
		}
	}

}

NAN_METHOD(x13)
{
	Isolate* isolate = info.GetIsolate();
	HandleScope scope(isolate);
	if (info.Length() < 1)
	{
		except("You must provide one argument.");
	}
	else
	{
		Local<Object> target = info[0]->ToObject();
		if (!node::Buffer::HasInstance(target))
		{
			except("Argument should be a buffer object.");

		}
		else
		{
			char * input = Buffer::Data(target);
			char* output = (char*)malloc(32);

			uint32_t input_len = Buffer::Length(target);

			x13_hash(input, output, input_len);

			auto result = node::Buffer::New(isolate, output, 32).ToLocalChecked();

			info.GetReturnValue().Set(result);
		}
	}

}

//*********


NAN_METHOD(boolberry)
{
	Isolate* isolate = info.GetIsolate();
	HandleScope scope(isolate);
	if (info.Length() < 2)
	{
		except("You must provide two arguments.");
	}
	else
	{
		Local<Object> target = info[0]->ToObject();
		Local<Object> target_spad = info[1]->ToObject();
		uint32_t height = 1;
		if (!node::Buffer::HasInstance(target))
		{
			except("Argument 1 should be a buffer object.");

		}
		else
		{
			if (!node::Buffer::HasInstance(target_spad))
			{
				except("Argument 2 should be a buffer object.");
				return;
			}

			if (info.Length() >= 3)
				if (info[2]->IsUint32())
					height = info[2]->ToUint32()->Uint32Value();
				else
				{
					except("Argument 3 should be an unsigned integer."); 
					return;
				}
					

			char * input = Buffer::Data(target);
			char * scratchpad = Buffer::Data(target_spad);
			char* output = (char*)malloc(32);

			uint32_t input_len = Buffer::Length(target);
			uint64_t spad_len = Buffer::Length(target_spad);

			boolberry_hash(input, input_len, scratchpad, spad_len, output, height);

			auto result = node::Buffer::New(isolate, output, 32).ToLocalChecked();

			info.GetReturnValue().Set(result);
		}
	}

}

NAN_METHOD(nist5)
{
	Isolate* isolate = info.GetIsolate();
	HandleScope scope(isolate);
	if (info.Length() < 1)
	{
		except("You must provide one argument.");
	}
	else
	{
		Local<Object> target = info[0]->ToObject();
		if (!node::Buffer::HasInstance(target))
		{
			except("Argument should be a buffer object.");

		}
		else
		{
			char * input = Buffer::Data(target);
			char* output = (char*)malloc(32);

			uint32_t input_len = Buffer::Length(target);

			nist5_hash(input, output, input_len);

			auto result = node::Buffer::New(isolate, output, 32).ToLocalChecked();

			info.GetReturnValue().Set(result);
		}
	}

}




NAN_METHOD(sha1)
{
	Isolate* isolate = info.GetIsolate();
	HandleScope scope(isolate);
	if (info.Length() < 1)
	{
		except("You must provide one argument.");
	}
	else
	{
		Local<Object> target = info[0]->ToObject();
		if (!node::Buffer::HasInstance(target))
		{
			except("Argument should be a buffer object.");

		}
		else
		{
			char * input = Buffer::Data(target);
			char* output = (char*)malloc(32);

			uint32_t input_len = Buffer::Length(target);

			sha1_hash(input, output, input_len);

			auto result = node::Buffer::New(isolate, output, 32).ToLocalChecked();

			info.GetReturnValue().Set(result);
		}
	}

}


NAN_METHOD(x15)
{
	Isolate* isolate = info.GetIsolate();
	HandleScope scope(isolate);
	if (info.Length() < 1)
	{
		except("You must provide one argument.");
	}
	else
	{
		Local<Object> target = info[0]->ToObject();
		if (!node::Buffer::HasInstance(target))
		{
			except("Argument should be a buffer object.");

		}
		else
		{
			char * input = Buffer::Data(target);
			char* output = (char*)malloc(32);

			uint32_t input_len = Buffer::Length(target);

			x15_hash(input, output, input_len);

			auto result = node::Buffer::New(isolate, output, 32).ToLocalChecked();

			info.GetReturnValue().Set(result);
		}
	}

}


NAN_METHOD(fresh)
{
	Isolate* isolate = info.GetIsolate();
	HandleScope scope(isolate);
	if (info.Length() < 1)
	{
		except("You must provide one argument.");
	}
	else
	{
		Local<Object> target = info[0]->ToObject();
		if (!node::Buffer::HasInstance(target))
		{
			except("Argument should be a buffer object.");

		}
		else
		{
			char * input = Buffer::Data(target);
			char* output = (char*)malloc(32);

			uint32_t input_len = Buffer::Length(target);

			fresh_hash(input, output, input_len);

			auto result = node::Buffer::New(isolate, output, 32).ToLocalChecked();

			info.GetReturnValue().Set(result);
		}
	}

}


void init(Local<Object> exports) {
	auto isolate = exports->GetIsolate();
	
	
	exports->Set(String::NewFromUtf8(isolate, "quark"), Nan::GetFunction(Nan::New<FunctionTemplate>(quark)).ToLocalChecked());
    exports->Set(String::NewFromUtf8(isolate,"x11"), Nan::GetFunction(Nan::New<FunctionTemplate>(x11)).ToLocalChecked());
    exports->Set(String::NewFromUtf8(isolate,"scrypt"), Nan::GetFunction(Nan::New<FunctionTemplate>(scryptHash)).ToLocalChecked());
    exports->Set(String::NewFromUtf8(isolate,"scryptn"), Nan::GetFunction(Nan::New<FunctionTemplate>(scryptn)).ToLocalChecked());
   // exports->Set(String::NewFromUtf8(isolate,"scryptjane"), Nan::GetFunction(Nan::New<FunctionTemplate>(scryptjane)).ToLocalChecked());
    exports->Set(String::NewFromUtf8(isolate,"keccak"), Nan::GetFunction(Nan::New<FunctionTemplate>(keccak)).ToLocalChecked());
    exports->Set(String::NewFromUtf8(isolate,"bcrypt"), Nan::GetFunction(Nan::New<FunctionTemplate>(bcrypt)).ToLocalChecked());
    exports->Set(String::NewFromUtf8(isolate,"skein"), Nan::GetFunction(Nan::New<FunctionTemplate>(skein)).ToLocalChecked());
    exports->Set(String::NewFromUtf8(isolate,"groestl"), Nan::GetFunction(Nan::New<FunctionTemplate>(groestl)).ToLocalChecked());
    exports->Set(String::NewFromUtf8(isolate,"groestlmyriad"), Nan::GetFunction(Nan::New<FunctionTemplate>(groestlmyriad)).ToLocalChecked());
    exports->Set(String::NewFromUtf8(isolate,"blake"), Nan::GetFunction(Nan::New<FunctionTemplate>(blake)).ToLocalChecked());
    exports->Set(String::NewFromUtf8(isolate,"fugue"), Nan::GetFunction(Nan::New<FunctionTemplate>(fugue)).ToLocalChecked());
    exports->Set(String::NewFromUtf8(isolate,"qubit"), Nan::GetFunction(Nan::New<FunctionTemplate>(qubit)).ToLocalChecked());
    exports->Set(String::NewFromUtf8(isolate,"hefty1"), Nan::GetFunction(Nan::New<FunctionTemplate>(hefty1)).ToLocalChecked());
    exports->Set(String::NewFromUtf8(isolate,"shavite3"), Nan::GetFunction(Nan::New<FunctionTemplate>(shavite3)).ToLocalChecked());
    exports->Set(String::NewFromUtf8(isolate,"cryptonight"), Nan::GetFunction(Nan::New<FunctionTemplate>(cryptonight)).ToLocalChecked());
    exports->Set(String::NewFromUtf8(isolate,"x13"), Nan::GetFunction(Nan::New<FunctionTemplate>(x13)).ToLocalChecked());
    exports->Set(String::NewFromUtf8(isolate,"boolberry"), Nan::GetFunction(Nan::New<FunctionTemplate>(boolberry)).ToLocalChecked());
    exports->Set(String::NewFromUtf8(isolate,"nist5"), Nan::GetFunction(Nan::New<FunctionTemplate>(nist5)).ToLocalChecked());
    exports->Set(String::NewFromUtf8(isolate,"sha1"), Nan::GetFunction(Nan::New<FunctionTemplate>(sha1)).ToLocalChecked());
    exports->Set(String::NewFromUtf8(isolate,"x15"), Nan::GetFunction(Nan::New<FunctionTemplate>(x15)).ToLocalChecked());
    exports->Set(String::NewFromUtf8(isolate,"fresh"), Nan::GetFunction(Nan::New<FunctionTemplate>(fresh)).ToLocalChecked());
}

NODE_MODULE(multihashing, init)
