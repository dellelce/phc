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
 * PHP source analysis
 *
 * We are outputting:
 *  - Classes defined in the source
 *    + Attributes
 *    + Functions
 *  - Functions defined
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


using namespace AST;

struct fn_scope {
	std::string fname, fclass;
	bool includes_file;
	std::vector <std::string> formal_params, local_vars, seen_vars;
};


class AST_Analyzer : public Visitor {
public:
	void children_class_def(Class_def* in) {
		std::string classname = *in->class_name->value;
		std::cout << "<class name=\"" << classname << "\">" << std::endl;

		for (unsigned int i = 0; i < in->members->size(); i++) {
			if (Method * method =  dynamic_cast<Method*> (in->members->at(i))) {
				std::string mn = *method->signature->method_name->value;
				std::cout << "<method>" << mn << "</method>" << std::endl;
			}
			else if (Attribute * attribute =  dynamic_cast<Attribute*> (in->members->at(i))) {
				//std::string mn = *method->signature->method_name->value();
			}
		}

		std::cout << "</class>" << std::endl;

		class_stack.push_back(classname);
		Visitor::children_class_def(in);
		class_stack.pop_back();
	}

	void children_method(Method* in) {
		std::string mn = *in->signature->method_name->value;
		if (class_stack.size() == 0) {
			std::cout << "<method>" << mn << "</method>" << std::endl;
		}

		function_stack.push_back(mn);
		Visitor::children_method(in);
		function_stack.pop_back();
	}

private:
	std::vector <std::string> class_stack;
	std::vector <std::string> function_stack;
};


extern "C" void load (Pass_manager* pm, Plugin_pass* pass) {
	pm->add_after_named_pass (pass, s("incl1"));
}

extern "C" void run_ast (PHP_script* in, Pass_manager* pm, String* option) {
	// Explore the PHP source
	in->visit (new AST_Analyzer());
}	


