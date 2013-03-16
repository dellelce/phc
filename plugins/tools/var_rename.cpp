/*
 * phc -- the open source PHP compiler
 * See doc/license/README.license for licensing information
 *
 * Author: davidgf
 * Description: plugin to rename the variables to something unreadable
 *              In order to handle correctly includes and other stuff the plugin uses a hash
 *              so that it renames the variables in a deterministic way (controlled by seed)
 */

#include "pass_manager/Plugin_pass.h"
#include "AST_visitor.h"
#include "process_ir/General.h"
#include <iostream>
#include <map>
#include <vector>
#include <stdio.h>
#include <stdlib.h>


typedef struct SHA1Context {
    unsigned Message_Digest[5];
    unsigned Length_Low, Length_High;
    unsigned char Message_Block[64];
    int Message_Block_Index;
    int Computed, Corrupted;
} SHA1Context;
#define SHA1CircularShift(bits,word) ((((word) << (bits)) & 0xFFFFFFFF) | ((word) >> (32-(bits))))
void SHA1ProcessMessageBlock(SHA1Context *);
void SHA1PadMessage(SHA1Context *);
void SHA1Reset(SHA1Context *context) {
    context->Length_Low = 0; context->Length_High = 0;
    context->Message_Block_Index= 0;
    context->Message_Digest[0] = 0x67452301; context->Message_Digest[1] = 0xEFCDAB89;
    context->Message_Digest[2] = 0x98BADCFE; context->Message_Digest[3] = 0x10325476;
    context->Message_Digest[4] = 0xC3D2E1F0; context->Computed   = 0;
    context->Corrupted  = 0;
}
int SHA1Result(SHA1Context *context) {
    if (context->Corrupted) return 0;
    if (!context->Computed) {
        SHA1PadMessage(context);
        context->Computed = 1;
    }
    return 1;
}
void SHA1Input(SHA1Context *context, const unsigned char *message_array, unsigned length) {
    if (!length) return;
    if (context->Computed || context->Corrupted) {
        context->Corrupted = 1;
        return;
    }

    while(length-- && !context->Corrupted) {
        context->Message_Block[context->Message_Block_Index++] = (*message_array & 0xFF);
        context->Length_Low += 8;
        context->Length_Low &= 0xFFFFFFFF;
        if (context->Length_Low == 0) {
            context->Length_High++;
            context->Length_High &= 0xFFFFFFFF;
            if (context->Length_High == 0) {
                context->Corrupted = 1;
            }
        }
        if (context->Message_Block_Index == 64) {
            SHA1ProcessMessageBlock(context);
        }
        message_array++;
    }
}

void SHA1ProcessMessageBlock(SHA1Context *context) {
    const unsigned K[] = {0x5A827999,0x6ED9EBA1,0x8F1BBCDC,0xCA62C1D6};
    int t; unsigned temp; unsigned W[80]; unsigned A, B, C, D, E;
    for(t = 0; t < 16; t++) {
        W[t] = ((unsigned) context->Message_Block[t * 4]) << 24;
        W[t] |= ((unsigned) context->Message_Block[t * 4 + 1]) << 16;
        W[t] |= ((unsigned) context->Message_Block[t * 4 + 2]) << 8;
        W[t] |= ((unsigned) context->Message_Block[t * 4 + 3]);
    }
    for(t = 16; t < 80; t++)
       W[t] = SHA1CircularShift(1,W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
    A = context->Message_Digest[0]; B = context->Message_Digest[1];
    C = context->Message_Digest[2]; D = context->Message_Digest[3];
    E = context->Message_Digest[4];
    for(t = 0; t < 20; t++){
        temp =  SHA1CircularShift(5,A) + ((B & C) | ((~B) & D)) + E + W[t] + K[0];
        temp &= 0xFFFFFFFF; E = D; D = C; C = SHA1CircularShift(30,B); B = A;A = temp;
    }
    for(t = 20; t < 40; t++) {
        temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[1];
        temp &= 0xFFFFFFFF; E = D; D = C; C = SHA1CircularShift(30,B); B = A; A = temp;
    }
    for(t = 40; t < 60; t++) {
        temp = SHA1CircularShift(5,A) + ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
        temp &= 0xFFFFFFFF; E = D; D = C; C = SHA1CircularShift(30,B); B = A; A = temp;
    }
    for(t = 60; t < 80; t++) {
        temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[3];
        temp &= 0xFFFFFFFF; E = D; D = C; C = SHA1CircularShift(30,B); B = A; A = temp;
    }
    context->Message_Digest[0] = (context->Message_Digest[0] + A) & 0xFFFFFFFF;
    context->Message_Digest[1] = (context->Message_Digest[1] + B) & 0xFFFFFFFF;
    context->Message_Digest[2] = (context->Message_Digest[2] + C) & 0xFFFFFFFF;
    context->Message_Digest[3] = (context->Message_Digest[3] + D) & 0xFFFFFFFF;
    context->Message_Digest[4] = (context->Message_Digest[4] + E) & 0xFFFFFFFF;
    context->Message_Block_Index = 0;
}

void SHA1PadMessage(SHA1Context *context) {
    if (context->Message_Block_Index > 55) {
        context->Message_Block[context->Message_Block_Index++] = 0x80;
        while(context->Message_Block_Index < 64)
            context->Message_Block[context->Message_Block_Index++] = 0;
        SHA1ProcessMessageBlock(context);
        while(context->Message_Block_Index < 56)
            context->Message_Block[context->Message_Block_Index++] = 0;
    }else{
        context->Message_Block[context->Message_Block_Index++] = 0x80;
        while(context->Message_Block_Index < 56)
            context->Message_Block[context->Message_Block_Index++] = 0;
    }
    context->Message_Block[56] = (context->Length_High >> 24) & 0xFF;
    context->Message_Block[57] = (context->Length_High >> 16) & 0xFF;
    context->Message_Block[58] = (context->Length_High >> 8) & 0xFF;
    context->Message_Block[59] = (context->Length_High) & 0xFF;
    context->Message_Block[60] = (context->Length_Low >> 24) & 0xFF;
    context->Message_Block[61] = (context->Length_Low >> 16) & 0xFF;
    context->Message_Block[62] = (context->Length_Low >> 8) & 0xFF;
    context->Message_Block[63] = (context->Length_Low) & 0xFF;
    SHA1ProcessMessageBlock(context);
}

void quick_sha1(const char * input, int size, char * output) {
	SHA1Context sha; SHA1Reset(&sha);
	SHA1Input(&sha, (const unsigned char *) input, size);
	if (SHA1Result(&sha)) {
		for (int i = 0; i < 5; i++) {
			output[i*4+0] = (sha.Message_Digest[i]>>24)&0xFF;
			output[i*4+1] = (sha.Message_Digest[i]>>16)&0xFF;
			output[i*4+2] = (sha.Message_Digest[i]>> 8)&0xFF;
			output[i*4+3] = (sha.Message_Digest[i]    )&0xFF;
		}
	}
}

// TODO: This should be pseudo-random, SHA1 could be bruteforced for short variables
std::string hash_variable(std::string input) {
	char out[20];
	quick_sha1(input.c_str(),input.size(),out);
	std::string output;
	for (int i = 0; i < 20; i++) {
		output += ('a'+(out[i]&0xF));
		output += ('a'+((out[i]>>4)&0xF));
	}
	return output;
}

using namespace AST;

class Var_Rename : public Visitor {
public:
	Var_Rename() {
		fn_scope fs;
		fs.fname = "_";
		fstack.push_back(fs); // No fn, main scope
	}
	
	void children_variable_name(VARIABLE_NAME* in) {
		// DO RENAMING STUFF
		fn_scope fs = fstack[0];
		std::string vname = *(dynamic_cast<VARIABLE_NAME*>(in))->value;

		// Check if the variable is a formal parameter of a function
		bool ok = false;
		for (unsigned int j = 0; j < fs.formal_params.size(); j++)
			if (fs.formal_params[j] == vname) {
				ok = true;
				break;
			}

		if (ok) {
			(dynamic_cast<VARIABLE_NAME*>(in))->value = new String(hash_variable(vname));
		}
		
		// Send to parent
		Visitor::children_variable_name(in);
	}

	// Rename formal parameters list
	void children_method(Method* in) {
		fn_scope fs;

		// Add the formal parameter list to a list of renamable variables
		List<Formal_parameter*> plist = *in->signature->formal_parameters;
		fs.fname = *in->signature->method_name->value;
		for (unsigned int i = 0; i < plist.size(); i++) {
			fs.formal_params.push_back(*plist.at(i)->var->variable_name->value);
		}

		// Push fn name to fstack
		fstack.push_back(fs);

		Visitor::children_method(in);

		// Pop fn name
		fstack.pop_back();
	}

protected:
	struct fn_scope {
		std::string fname;
		std::vector <std::string> formal_params;
		std::vector <std::string> local_vars;
	};
	std::vector <fn_scope> fstack;
};

extern "C" void load (Pass_manager* pm, Plugin_pass* pass) {
	pm->add_after_named_pass (pass, s("incl1"));
}

extern "C" void run_ast (PHP_script* in, Pass_manager* pm, String* option) {
	in->visit (new Var_Rename ());
}	

