#include "scs.hpp"

using namespace std;
using namespace scs;

void test1()
{
	auto re = get_tokens(R"(+-*/.,"this is a test str\n",'c','\t',"","\t$$$$ $$$$ + - * /"
							"test")");
	for (auto i : re)
		cout << (int)i.type << '\t' << i.content << endl;
}

void test2()
{
	parser p;
	p.parse(std::string(R"(
(
		(test 1 2)
		(add a b)
		(add (add 1 2) a)
		(print (add str "string test"))
		(print (add c '\t'))
		(assign f 10.2)
		(print 1.0 2.0 3.0 f 1 "test my list script\n")
		(!= (& (| 1 2) (+ 3 4)) (% 4 2))
		(--)
)
		)") + std::string("\n"));
	p.debug_print_ast();
}

void test3()
{
	interpreter in;
	add_core_content(in);
	std::string str = R"((eval
	(eval
		(print 12.33 '\t' 111.231 '\n')
	)
	(print 1 2 3 '\n')
	(print "hello scs\n")
	(def int a 0)
	(def int b)
	(read a)
	(print a ' ' b '\n')
	(eval
		(read b)
		(print b '\n')
	)
	(
		(def_func println (int n)
			(print n '\n')
		) 
	3)
	(def_func println (string str)
		(print str '\n')
	)
	(println "test function")
	)
	(print "test other block\n")
)";
	in.run_from_string(str);
}
int main()
{
	//test1();
	test2();
	test3();
	return 0;
}