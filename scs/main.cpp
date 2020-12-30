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
	std::string str = R"((eval
	(eval
		(print 12.33 '\t' 111.231 '\n')
	)
	(print 1 2 3 '\n')
	(print "hello scs\n")
	(var int a 0)
	(var int b)
	(read a)
	(print a ' ' b '\n')
	(eval
		(read b)
		(print b '\n')
	)
	(
		(func println (int n)
			(print n '\n')
		) 
	3)
	(func println (string str)
		(print str '\n')
	)
	(println "test function")
	)
	(print "test other block\n")
)";
	in.run_from_string(str);
}
void test4()
{
	interpreter in;
	std::string str = R"(
	(var int i)
	(var float f)
	(var char c)
	(var string str)
	(const string cstr "test const string\n")
	(read i f c str)
	(print i ' ' f ' ' c ' ' str '\n')
	(print true '\n')
	(print cstr)
)";
	in.run_from_string(str);
}
void test5()
{
	interpreter in;
	std::string str = R"(
	(if true (print "hello state condition\n"))
	(if false (print "true\n") (print "false\n"))
	(var float f 3.14)
	(print f ' ' 0xff '\n')
	(for (var int i 0) (< i 10) (= i (+ i 1))
		(print i '\n')
	)
	(print "------------------- \n")
	(for (var int i 9) (>= i 0) (+= i -1)
		(print i '\n')
	)
	(var string str)
	(read str)
	(for (var int i 0) (< i (length_of str)) (+= i 1)
		(print i " :\t" (at str i) '\n')
	)
	(var char c)
	(read c)
	(= (at str 0) c)
	(print str '\n')
	(print (== (at str 0) c ) '\n')
	(print (== c '1') '\n')
)";
	in.run_from_string(str);
}
int main()
{
	//test1();
	//test2();
	//test3();
	//test4();
	test5();
	return 0;
}