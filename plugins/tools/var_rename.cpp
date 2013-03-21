/*
 * phc -- the open source PHP compiler
 * See doc/license/README.license for licensing information
 *
 * Author: davidgf
 * Description: plugin to rename the variables to something unreadable
 *              In order to handle correctly includes and other stuff the plugin uses a hash
 *              so that it renames the variables in a deterministic way (controlled by seed)
 */

/**
 * Safe rules for variable renaming
 *
 * For each scope:
 *  Rename variables which are formal parameters for a function
 *  Rename variables which are first used in the left part of an assignment
 * 
 * The main restriction is file inclusion. That's why we cannot rename all
 * the variables. The two main problems are:
 *  - Variables defined in an included file
 *    + Solution: Do not rename variables which are first used in the right
 *      part of an assignment, only rename if they are first used in the left part.
 *  - Variables used in an included file:
 *    + Solution: We can decide not to rename variables if there's an inclusion after
 *      their first assignment. This is difficult to model, as the inclusion occurs dinamically
 *      with the code flow.
 * We should'n rename class attributes. It could be bad if the class is used in another file
 *
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
	for (int i = 0; i < 5; i++) {
		output += ('a'+(out[i]&0xF));
		output += ('a'+((out[i]>>4)&0xF));
	}
	return output;
}

using namespace AST;

struct fn_scope {
	std::string fname, fclass;
	bool includes_file;
	std::vector <std::string> formal_params, local_vars, seen_vars;
};


class Var_Rename_Base : public Visitor {
public:
	Var_Rename_Base () {
		curr_class.push_back("");
		curr_function.push_back("");

		fn_scope fs;
		fs.fname = "";
		fs.fclass = "";
		fs.includes_file = true;
		fstack.push_back(fs);
	}

	std::vector <fn_scope> getfstack() {
		return fstack;
	}

	// Context tracking
	// Track in which class and/or method definition we are
	void children_class_def(Class_def* in) {
		// Push current class definition
		curr_class.push_back(*(dynamic_cast<CLASS_NAME*>(in->class_name))->value);

		Visitor::children_class_def(in);

		curr_class.pop_back();
	}
	// Track the current function
	void children_method(Method* in) {
		std::string mn = *in->signature->method_name->value;
		curr_function.push_back(mn);

		Visitor::children_method(in);

		curr_function.pop_back();
	}

private:
	std::vector < std::string > curr_class, curr_function;

protected:
	std::vector <fn_scope> fstack;

	std::string getCurrClass() const {
		return curr_class.back();
	}

	fn_scope * getCurrScope() {
		for (unsigned int i = 0; i < fstack.size(); i++) {
			if (fstack[i].fname == curr_function.back() and 
				fstack[i].fclass == curr_class.back()) 

				return &fstack[i];
		}
		return NULL;
	}

	static bool varInList(fn_scope * cs, std::string varname) {
		bool inlist = false;
		for (unsigned int i = 0; i < cs->seen_vars.size(); i++) {
			if (cs->seen_vars[i] == varname) {
				inlist = true;
				break;
			}
		}
		for (unsigned int i = 0; i < cs->local_vars.size(); i++) {
			if (cs->local_vars[i] == varname) {
				inlist = true;
				break;
			}
		}
		return inlist;
	}
};




class Var_Rename_Explore : public Var_Rename_Base {
public:
	Var_Rename_Explore () {}

	// Look for variable production
	void children_assignment(Assignment* in) {
		fn_scope * cs = getCurrScope();
		if (cs != NULL) {
			if (in->variable->variable_name->classid() == VARIABLE_NAME::ID) {
				std::string varname = *(dynamic_cast<VARIABLE_NAME*>(in->variable->variable_name))->value;

				if (not Var_Rename_Base::varInList(cs,varname) and in->variable->target == NULL)
					cs->local_vars.push_back(varname);
			}
		}

		Var_Rename_Base::children_assignment(in);		
	}

	// Production occurs in foreach too
	void children_foreach(Foreach* in) {
		fn_scope * cs = getCurrScope();
		if (cs != NULL) {
			if (in->key) {
				std::string varname = *(dynamic_cast<VARIABLE_NAME*>(in->key->variable_name))->value;
				if (not Var_Rename_Base::varInList(cs,varname))
					cs->local_vars.push_back(varname);
			}
			if (in->val) {
				std::string varname = *(dynamic_cast<VARIABLE_NAME*>(in->val->variable_name))->value;
				if (not Var_Rename_Base::varInList(cs,varname))
					cs->local_vars.push_back(varname);
			}
		}

		Var_Rename_Base::children_foreach(in);
	}

	// Look for variable usage
	void children_variable_name(VARIABLE_NAME* in) {
		fn_scope * cs = getCurrScope();
		if (cs != NULL) {
			if (in->classid() == VARIABLE_NAME::ID) {
				std::string varname = *(dynamic_cast<VARIABLE_NAME*>(in))->value;

				// Add the variable to the "seen" list
				bool alreadyseen = false;
				for (unsigned int i = 0; i < cs->seen_vars.size(); i++) {
					if (cs->seen_vars[i] == varname) {
						alreadyseen = true;
						break;
					}
				}
				if (not alreadyseen) {
					cs->seen_vars.push_back(varname);
				}
			}
		}

		Var_Rename_Base::children_variable_name(in);
	}

	// Look for "require", "include", "require_once" of "include_once"
	void children_method_invocation(Method_invocation* in) {
		fn_scope * fs = getCurrScope();
		if (fs != NULL) {
			std::string mname = *(dynamic_cast<METHOD_NAME*>(in->method_name))->value;
			if (mname == "include" or mname == "include_once" or 
				mname == "require" or mname == "require_once") {

				fs->includes_file = true;
			}
		}

		Var_Rename_Base::children_method_invocation(in);
	}

	// Add the functions to the function list with the formal parameters
	void children_method(Method* in) {
		std::string mn = *in->signature->method_name->value;

		fn_scope fs;
		fs.fname = mn;
		fs.fclass = getCurrClass();
		fs.includes_file = false;

		List<Formal_parameter*> plist = *in->signature->formal_parameters;
		for (unsigned int i = 0; i < plist.size(); i++) {
			fs.formal_params.push_back(*plist.at(i)->var->variable_name->value);
		}

		fstack.push_back(fs);

		Var_Rename_Base::children_method(in);
	}
};


class Var_Rename : public Var_Rename_Base {
public:
	Var_Rename(std::vector <fn_scope> fstack) {
		this->fstack = fstack;
	}

	void children_variable_name(VARIABLE_NAME* in) {
		fn_scope * cs = getCurrScope();
		if (cs != NULL) {
			if (in->classid() == VARIABLE_NAME::ID) {
				std::string varname = *(dynamic_cast<VARIABLE_NAME*>(in))->value;

				// Check wheter we can rename it
				bool renamable = false;

				for (unsigned int i = 0; i < cs->formal_params.size(); i++) {
					if (cs->formal_params[i] == varname) {
						renamable = true;
						break;
					}
				}
				for (unsigned int i = 0; i < cs->local_vars.size(); i++) {
					if (cs->local_vars[i] == varname) {
						renamable = true;
						break;
					}
				}
				if (cs->includes_file) renamable = false;

				if (renamable) {
					(dynamic_cast<VARIABLE_NAME*>(in))->value = new String(hash_variable(varname));
				}
			}
		}

		Var_Rename_Base::children_variable_name(in);
	}
};

extern "C" void load (Pass_manager* pm, Plugin_pass* pass) {
	pm->add_after_named_pass (pass, s("incl1"));
}

extern "C" void run_ast (PHP_script* in, Pass_manager* pm, String* option) {
	// Explore the PHP source
	Var_Rename_Explore * explorer = new Var_Rename_Explore();
	in->visit (explorer);

	// Debug info
	if (true) {
		std::vector <fn_scope> fstack = explorer->getfstack();
		for (unsigned int i = 0; i < fstack.size(); i++) {
			std::cerr << " + " << fstack[i].fclass << "." << fstack[i].fname << " includes? " << 
				fstack[i].includes_file << std::endl;
			for (unsigned int j = 0; j < fstack[i].formal_params.size(); j++) {
				std::cerr << "   * " << fstack[i].formal_params[j] << std::endl;
			}
			for (unsigned int j = 0; j < fstack[i].local_vars.size(); j++) {
				std::cerr << "   - " << fstack[i].local_vars[j] << std::endl;
			}

			std::cerr << std::endl;
		}
	}

	in->visit (new Var_Rename (explorer->getfstack()));
}	


