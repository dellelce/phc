/*
 * phc -- the open source PHP compiler
 * See doc/license/README.license for licensing information
 *
 * Author: davidgf
 * Description: plugin to process the MIR tree for obfuscating string by using encription
 */

#include "pass_manager/Plugin_pass.h"
#include "AST_visitor.h"
#include "process_ir/General.h"
#include <iostream>
#include <stdio.h>
#include <stdlib.h>

unsigned int rndgen(unsigned int prev) {
	return 69069*prev+1234567;
}

std::string crypt_string (std::string in, unsigned int code) {
	std::string out;
	for (int i = 0; i < in.size(); i++) {
		code = rndgen(code);

		int num = *(unsigned char*)&in[i];
		num ^= (code & 0xFF);
		
		out += ('a'+ (num&0xF));
		out += ('a'+ ((num>>4)&0xF));
	}
	return out;
}


using namespace MIR;

class Crypt_Strings : public Visitor {
private:
	AST::PHP_script * auxfuncts;
public:
	Crypt_Strings() {}
	
	void pre_assign_var(Assign_var* in) {
		if (in->rhs->classid() == STRING::ID) {
			// Get random code
			unsigned int code = rand();
			
			// Get original string
			std::string original = *(dynamic_cast<STRING*>(in->rhs))->value;
			if (original.size() == 0) return;  // Do not crypt empty strings
			original = crypt_string(original,code);
			// Create parameters
			STRING * str1 = new STRING(new String(original));
			INT * int2 = new INT(code);
			List<Actual_parameter*> * params = new List<Actual_parameter*>();
			params->push_back(new Actual_parameter(false,str1));
			params->push_back(new Actual_parameter(false,int2));
			// Create method reference
			METHOD_NAME * method = new METHOD_NAME(new String("sdd"));
			// Create the call
			Method_invocation * call = new Method_invocation(NULL,method,params);
			
			// Substitute the string with the call
			in->rhs = call;
		}
	}

};

extern "C" void load (Pass_manager* pm, Plugin_pass* pass) {
	pm->add_after_named_pass (pass, s("ast"));
	pm->add_after_named_pass (pass, s("mir"));
}

// Be careful or the function will become recursive!
const char decode_function[] = 
	"<?php \n \
	function sdd($a,$b) { \
		$out = ''; \
		for ($i = 0; $i < strlen($a); $i+=2) { \
			$b = 69069*$b+1234567; \
			$b &= 0xffffffff; \
			$lo = ord($a[$i])-97; \
			$hi = ord($a[$i+1])-97; \
			$num = $lo + $hi*16;  \
			$num = ($num ^ $b) & 255; \
			$out .= chr($num); \
		} \
		return $out; \
	}  \
	\n ?> \
	";

extern "C" void run_ast (AST::PHP_script* in, Pass_manager* pm, String* option) {
	// Add function
	AST::PHP_script * script = parse_code (new String(decode_function), new String("decodefunction.php"), 1);
	assert(script);
	pm->run_until (s("ast"), script);

	in->statements->push_front_all (script->statements);
}

extern "C" void run_mir (PHP_script* in, Pass_manager* pm, String* option) {
	in->visit (new Crypt_Strings ());
}	

