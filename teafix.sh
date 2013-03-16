# cmdline is regenerated, install gengetopt

touch src/generated/{AST,HIR,MIR,MICG}* 
rm -rf src/generated/cmdline.{c,h}
touch src/generated/{AST,HIR,MIR,MICG}*
touch src/generated/keywords.h
touch src/generated/lex.yy.cc
touch src/generated/php_{dot,parser}.tab.{cpp,hpp}

