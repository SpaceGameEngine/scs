#pragma once
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <functional>
#include <fstream>
#include <unordered_map>
#include <optional>

#ifdef _WIN32
#include <Windows.h>
#endif

namespace scs
{
	void throw_error(const std::string& str)
	{
		std::cerr << str << std::endl;
#ifdef _WIN32
		DebugBreak();
#else
		abort();
#endif
	}

	enum class token_type
	{
		null = 0,
		integer = 1,
		decimal = 2,
		string = 3,
		character_content = 4,
		string_content = 5,
		exclamation_mark = 6,		//!
		hash_mark = 7,				//#
		dollar_mark = 8,			//$
		mod_mark = 9,				//%
		and_mark = 10,				//&
		left_bracket = 11,			//(
		right_bracket = 12,			//)
		mul_mark = 13,				//*
		add_mark = 14,				//+
		comma = 15,					//,
		sub_mark = 16,				//-
		dot = 17,					//.
		slash = 18,					///
		colon = 19,					//:
		semicolon = 20,				//;
		less_mark = 21,				//<
		equal_mark = 22,			//=
		biger_mark = 23,			//>
		question_mark = 24,			//?
		at_mark = 25,				//@
		left_square_bracket = 26,	//[
		backslash = 27,				//\ 
		right_square_bracket = 28,	//]
		disyllabic = 29,			//^
		left_curly_bracket = 30,	//{
		vertical = 31,				//|
		right_curly_bracket = 32,	//}
		tilde = 33,					//~
		less_equal = 34,			//<=
		not_equal = 35,				//!=
		bigger_equal = 36,			//>=
		point_to = 37,				//->
		belong_to = 38,				//::
		option = 39					//--
	};

	enum class parse_status
	{
		normal = 0,
		in_character_content = 1,
		in_string_content = 2
	};

	struct token
	{
		token_type type;
		std::string content;

		token(token_type t = token_type::null, const std::string s = "")
			:type(t), content(s)
		{}
	};

	inline bool is_next_line(char c)
	{
		return c == '\n' || c == '\r';
	}

	inline bool is_divide(char c)
	{
		return is_next_line(c) || c == '\t' || c == ' ';
	}

	inline bool is_integer(const std::string& str)
	{
		if (str.empty())
			return false;
		else
		{
			if (str.size() <= 2)
			{
				for (auto& i : str)
					if (i < '0' || i>'9')
						return false;
				return true;
			}
			else
			{
				if (str[0] < '0' || str[0]>'9')
					return false;
				if ((str[1] < '0' || str[1]>'9') && str[1] != 'x' && str[1] != 'b')
					return false;
				for (std::size_t i = 2; i < str.size(); i++)
				{
					if (str[i] < '0' || str[i]>'9')
						return false;
				}
				return true;
			}
		}
	}

	inline bool is_decimal(const std::string& str)
	{
		//notice do not add suffix f
		auto p = str.find(".");
		if (p == str.npos)
		{
			for (auto& i : str)
				if (i < '0' || i > '9')
					return false;
			return true;
		}
		else
		{
			if (p == 0)
				return false;
			for (int i = 0; i < p; i++)
				if (str[i] < '0' || str[i]>'9')
					return false;
			for (int i = p + 1; i < str.size(); i++)
				if (str[i] < '0' || str[i]>'9')
					return false;
			return true;
		}
	}

	inline bool is_normal_string(const std::string& str)
	{
		if (str.size() == 0)
			return false;
		if ((str[0] >= '0' && str[0] <= '9') ||
			(((str[0] >= 'a' && str[0] <= 'z') == false) &&
				((str[0] >= 'A' && str[0] <= 'Z') == false) &&
				(str[0] != '_')))
			return false;

		for (std::size_t i = 1; i < str.size(); i++)
		{
			if (((str[0] >= 'a' && str[0] <= 'z') == false) &&
				((str[0] >= 'A' && str[0] <= 'Z') == false) &&
				(str[0] != '_'))
				return false;
		}

		return true;
	}

	inline token_type get_multi_symbol_type(const std::string& str)
	{
		if (str == "<=")
			return token_type::less_equal;
		else if (str == "!=")
			return token_type::not_equal;
		else if (str == ">=")
			return token_type::bigger_equal;
		else if (str == "->")
			return token_type::point_to;
		else if (str == "::")
			return token_type::belong_to;
		else if (str == "--")
			return token_type::option;
		else
			return token_type::null;
	}

	inline std::string to_char(const std::string& str)
	{
		if (str.size() == 3)
			return str.substr(1, 1);
		else
		{
			//todo think about utf8 character set

			//now only concerned backslash and only these
			std::string s = str.substr(1, str.size() - 2);
			if (s == R"(\\)")
				return "\\";
			else if (s == R"(\n)")
				return "\n";
			else if (s == R"(\r)")
				return "\r";
			else if (s == R"(\t)")
				return "\t";
			else if (s == R"(\')")
				return "\'";
			else if (s == R"(\")")
				return "\"";
			else if (s == R"(\0)")
				return "\0";
			else
				throw_error("this is not a valid character");
		}
	}

	inline char get_tran(char c)
	{
		if (c == '\\')
			return '\\';
		else if (c == 'n')
			return '\n';
		else if (c == 'r')
			return '\r';
		else if (c == 't')
			return '\t';
		else if (c == '\'')
			return '\'';
		else if (c == '\"')
			return '\"';
		else if (c == '0')
			return '\0';
		else
		{
			throw_error("this is not a valid \\ character");
			return 0;
		}
	}

	inline token_type get_symbol_type(char c)
	{
		if (c == '!')
			return token_type::exclamation_mark;
		else if (c == '#')
			return token_type::hash_mark;
		else if (c == '$')
			return token_type::dollar_mark;
		else if (c == '%')
			return token_type::mod_mark;
		else if (c == '&')
			return token_type::and_mark;
		else if (c == '(')
			return token_type::left_bracket;
		else if (c == ')')
			return token_type::right_bracket;
		else if (c == '*')
			return token_type::mul_mark;
		else if (c == '+')
			return token_type::add_mark;
		else if (c == ',')
			return token_type::comma;
		else if (c == '-')
			return token_type::sub_mark;
		else if (c == '.')
			return token_type::dot;
		else if (c == '/')
			return token_type::slash;
		else if (c == ':')
			return token_type::colon;
		else if (c == ';')
			return token_type::semicolon;
		else if (c == '<')
			return token_type::less_mark;
		else if (c == '=')
			return token_type::equal_mark;
		else if (c == '>')
			return token_type::biger_mark;
		else if (c == '?')
			return token_type::question_mark;
		else if (c == '@')
			return token_type::at_mark;
		else if (c == '[')
			return token_type::left_square_bracket;
		else if (c == '\\')
			return token_type::backslash;
		else if (c == ']')
			return token_type::right_square_bracket;
		else if (c == '^')
			return token_type::disyllabic;
		else if (c == '{')
			return token_type::left_curly_bracket;
		else if (c == '|')
			return token_type::vertical;
		else if (c == '}')
			return token_type::right_curly_bracket;
		else if (c == '~')
			return token_type::tilde;
		else
			return token_type::null;

	}

	//can only be called by get_tokens
	inline token get_token(const std::string& str)
	{
		if (str.size() >= 2 && str[0] == '"' && str[str.size() - 1] == '"')
		{
			return token(token_type::string_content, str.substr(1, str.size() - 2));
		}
		else if (str.size() >= 3 && str[0] == '\'' && str[str.size() - 1] == '\'')
		{
			return token(token_type::character_content, str.substr(1, str.size() - 2));
		}
		else if (is_integer(str))
		{
			return token(token_type::integer, str);
		}
		else if (is_decimal(str))
		{
			return token(token_type::decimal, str);
		}
		else if (is_normal_string(str))
		{
			return token(token_type::string, str);
		}
		else if (str.size() == 1)
		{
			auto t = get_symbol_type(str[0]);
			if (t != token_type::null)
				return token(t, str);
		}
		else if (get_multi_symbol_type(str) != token_type::null)
		{
			return token(get_multi_symbol_type(str), str);
		}

		throw_error("can not transform this string");
	}

	inline std::vector<token> get_tokens(const std::string& str)
	{
		std::string sbuf;
		std::vector<token> re;
		token_type tbuf;
		parse_status status = parse_status::normal;
		bool is_tran = false;

		for (int i = 0; i < str.size(); i++)
		{
			const char& c = str[i];
			if (status == parse_status::normal)
			{
				if (sbuf.empty() == false)
				{
					if (is_divide(c) || get_symbol_type(c) != token_type::null || c == '\'' || c == '\"' || get_symbol_type(sbuf[0]) != token_type::null)
					{
						if (is_integer(sbuf) && (get_symbol_type(c) == token_type::dot))
						{
							sbuf += c;
							continue;
						}
						else if (get_multi_symbol_type(sbuf + c) != token_type::null)
						{
							re.emplace_back(get_token(sbuf + c));
							sbuf.clear();
						}
						else
						{
							re.emplace_back(get_token(sbuf));
							sbuf.clear();
							if (!is_divide(c))
								goto normal_new_character;
						}
					}
					else
					{
						sbuf += c;
					}
				}
				else
				{
				normal_new_character:
					if (is_divide(c))
						continue;
					sbuf += c;
					if (c == '\"')
					{
						status = parse_status::in_string_content;
						is_tran = false;
					}
					else if (c == '\'')
					{
						status = parse_status::in_character_content;
						is_tran = false;
					}
				}
			}
			else if (status == parse_status::in_character_content)
			{
				if (is_next_line(c))
					throw_error("less of \'");
				if (sbuf.size() == 1)
				{
					sbuf += c;
					if (c == '\\')
						is_tran = true;
					else
						is_tran = false;
					if (c == '\'' || c == '\"')
					{
						throw_error("this is not a valid character");
					}
				}
				else if (sbuf.size() == 2)
				{
					if (is_tran)
					{
						sbuf[sbuf.size() - 1] = get_tran(c);
						is_tran = false;
					}
					else
					{
						if (c == '\'')
						{
							re.emplace_back(get_token(sbuf + '\''));
							sbuf.clear();
							status = parse_status::normal;
						}
						else
						{
							throw_error("less of \'");
						}
					}
				}
				else if (sbuf.size() == 3)
				{
					if (c == '\'')
					{
						re.emplace_back(get_token(sbuf + '\''));
						sbuf.clear();
						status = parse_status::normal;
					}
					else
					{
						throw_error("less of \'");
					}
				}
			}
			else if (status == parse_status::in_string_content)
			{
				if (is_next_line(c))
					throw_error("less of \"");
				if (is_tran)
				{
					sbuf[sbuf.size() - 1] = get_tran(c);
					is_tran = false;
				}
				else
				{
					if (c == '\\')
					{
						sbuf += c;
						is_tran = true;
					}
					else if (c == '\"')
					{
						re.emplace_back(get_token(sbuf + '\"'));
						sbuf.clear();
						status = parse_status::normal;
					}
					else
					{
						sbuf += c;
					}
				}
			}
		}

		if (sbuf.empty() == false)
		{
			if (is_divide(sbuf[0]) == false)
				re.emplace_back(get_token(sbuf));
			sbuf.clear();
		}

		return re;
	}

	enum class content_type
	{
		null = 0,
		variable = 1,
		constant_integer = 2,
		constant_decimal = 3,
		constant_character = 4,
		constant_string = 5
	};

	struct ast_node
	{
		ast_node* pfather = nullptr;
		std::string content;
		content_type type;
		std::vector<ast_node*> pchildren;
	};

	/*
	S' : S $
	S : B S
	  | null
	B : (Bs)
	  | String
	  | Integer
	  | Decimal
	  | CharacterContent
	  | StringContent
	Bs : B Bs
	*/

	class parser
	{
	public:
		inline void parse(const std::string& str)
		{
			tokens = get_tokens(str);
			proot = new ast_node;
			proot->type = content_type::null;
			nodes.push_back(proot);
			size_t index = 0;
			while (index < tokens.size())
			{
				index = parse_block(proot, index);
			}
		}
		inline void debug_print_ast()
		{
			if (!proot)
			{
				throw_error("need parse first");
			}
			debug_print(proot, 0);
		}
		inline ~parser()
		{
			for (auto& i : nodes)
				delete i;
		}
		inline ast_node* get_ast_root()
		{
			if (!proot)
			{
				throw_error("need parse first");
			}
			return proot;
		}
	private:
		inline void debug_print(ast_node* pnow, int depth)
		{
			for (int i = 0; i < depth; i++)
				std::cout << "--";
			std::cout << ">" << pnow->content << " : " << (int)pnow->type << std::endl;
			for (auto& i : pnow->pchildren)
			{
				if (i)
					debug_print(i, depth + 1);
			}
		}

		inline std::size_t parse_block(ast_node* pfa, std::size_t index)
		{
			if (index == tokens.size())
				return index;	//over
			if (tokens[index].type == token_type::left_bracket)
			{
				auto pnode = new ast_node;
				nodes.push_back(pnode);
				pfa->pchildren.push_back(pnode);
				pnode->pfather = pfa;
				pnode->type = content_type::null;
				return parse_blocks(pnode, index + 1);
			}
			else if (tokens[index].type == token_type::string)
			{
				auto pnode = new ast_node;
				nodes.push_back(pnode);
				pfa->pchildren.push_back(pnode);
				pnode->pfather = pfa;
				pnode->type = content_type::variable;
				pnode->content = tokens[index].content;
				return index + 1;
			}
			else if (tokens[index].type == token_type::integer)
			{
				auto pnode = new ast_node;
				nodes.push_back(pnode);
				pfa->pchildren.push_back(pnode);
				pnode->pfather = pfa;
				pnode->type = content_type::constant_integer;
				pnode->content = tokens[index].content;
				return index + 1;
			}
			else if (tokens[index].type == token_type::decimal)
			{
				auto pnode = new ast_node;
				nodes.push_back(pnode);
				pfa->pchildren.push_back(pnode);
				pnode->pfather = pfa;
				pnode->type = content_type::constant_decimal;
				pnode->content = tokens[index].content;
				return index + 1;
			}
			else if (tokens[index].type == token_type::character_content)
			{
				auto pnode = new ast_node;
				nodes.push_back(pnode);
				pfa->pchildren.push_back(pnode);
				pnode->pfather = pfa;
				pnode->type = content_type::constant_character;
				pnode->content = tokens[index].content;
				return index + 1;
			}
			else if (tokens[index].type == token_type::string_content)
			{
				auto pnode = new ast_node;
				nodes.push_back(pnode);
				pfa->pchildren.push_back(pnode);
				pnode->pfather = pfa;
				pnode->type = content_type::constant_string;
				pnode->content = tokens[index].content;
				return index + 1;
			}
			else if (tokens[index].type == token_type::less_equal ||
				tokens[index].type == token_type::not_equal ||
				tokens[index].type == token_type::bigger_equal ||
				tokens[index].type == token_type::point_to ||
				tokens[index].type == token_type::belong_to ||
				tokens[index].type == token_type::add_mark ||
				tokens[index].type == token_type::sub_mark ||
				tokens[index].type == token_type::mul_mark ||
				tokens[index].type == token_type::slash ||
				tokens[index].type == token_type::mod_mark ||
				tokens[index].type == token_type::and_mark ||
				tokens[index].type == token_type::exclamation_mark ||
				tokens[index].type == token_type::vertical ||
				tokens[index].type == token_type::option
				)
			{
				//symbol
				auto pnode = new ast_node;
				nodes.push_back(pnode);
				pfa->pchildren.push_back(pnode);
				pnode->pfather = pfa;
				pnode->type = content_type::variable;
				pnode->content = tokens[index].content;
				return index + 1;
			}
		}
		inline std::size_t parse_blocks(ast_node* pfa, std::size_t index)
		{
			if (index >= tokens.size())
			{
				throw_error("unexcepted end");
				return index;
			}
			if (tokens[index].type == token_type::right_bracket)
			{
				return index + 1;
			}
			else
			{
				while (tokens[index].type != token_type::right_bracket && index < tokens.size())
				{
					index = parse_block(pfa, index);
				}
				if (index >= tokens.size())
				{
					throw_error("unexcepted end");
					return index;
				}
				else if (tokens[index].type == token_type::right_bracket)
				{
					return index + 1;
				}
				else
				{
					throw_error("unknown parse");
					return index;
				}
			}
		}
	private:
		std::vector<token> tokens;
		std::vector<ast_node*> nodes;
		ast_node* proot;
	};

	class backend
	{
	public:
		friend class context;

		struct variable
		{
			std::string type_name;
			void* pcontent;

			variable(const std::string& tn = "", void* p = nullptr)
				:type_name(tn), pcontent(p)
			{}

			template<typename T>
			T& as()const
			{
				return *reinterpret_cast<T*>(pcontent);
			}
		};

		struct type_information
		{
			std::string type_name;
			std::function<void* ()> default_construction_func;
			std::function<void(void*)> destruction_func;
			std::function<void(void*, void*)> copy_func;		//dest src
		};

		struct function;

		class context
		{
		public:
			inline context(context* pf = nullptr)
				:pfather(pf), unname_count(0)
			{}

			inline ~context()
			{
				for (auto& i : variables)
				{
					get_type(i.second.type_name).destruction_func(i.second.pcontent);
				}
			}

			template<typename T, typename... Args>
			inline variable& new_variable(const std::string& name, const std::string& type_name, Args&&... args)
			{
				auto iter = variables.find(name);
				if (iter != variables.end())
					throw_error("the variable has already existed");
				get_type(type_name);
				variables.emplace(std::make_pair(name, variable{ type_name, new T(std::forward<Args>(args)...) }));
				return variables[name];
			}

			inline variable& move_existed_variable(const std::string& name, const variable& v)
			{
				auto iter = variables.find(name);
				if (iter != variables.end())
					throw_error("the variable has already existed");
				variables.emplace(std::make_pair(name, v));
				return variables[name];
			}

			template<typename T, typename... Args>
			inline variable& new_unnamed_variable(const std::string& type_name, Args&&... args)
			{
				return new_variable<T>("non_name_var@" + std::to_string(unname_count++), type_name, std::forward<Args>(args)...);
			}

			inline const variable& find_variable(const std::string& name)const
			{
				const context* vc = this;
				while (vc != nullptr)
				{
					auto iter = vc->variables.find(name);
					if (iter != vc->variables.end())
						return iter->second;
					else
						vc = vc->pfather;
				}
				throw_error("do not have this variable");
			}

			inline bool has_variable(const std::string& name)const
			{
				const context* vc = this;
				while (vc != nullptr)
				{
					auto iter = vc->variables.find(name);
					if (iter != vc->variables.end())
						return true;
					else
						vc = vc->pfather;
				}
				return false;
			}

			inline void add_type(const type_information& t)
			{
				types.insert(std::make_pair(t.type_name, t));
			}

			inline const type_information& get_type(const std::string& type_name)const
			{
				const context* vc = this;
				while (vc != nullptr)
				{
					auto iter = vc->types.find(type_name);
					if (iter != vc->types.end())
						return iter->second;
					else
						vc = vc->pfather;
				}
				throw_error("do not have this type");
			}

			inline std::optional<const type_information*> find_type(const std::string& type_name)const
			{
				const context* vc = this;
				while (vc != nullptr)
				{
					auto iter = vc->types.find(type_name);
					if (iter != vc->types.end())
						return &iter->second;
					else
						vc = vc->pfather;
				}
				return std::nullopt;
			}

			inline void add_function(const function& f)
			{
				auto fname = resolve_function_name(f);
				if (functions.find(fname) == functions.end())
					functions.insert(std::make_pair(fname, f));
				else
					throw_error("the function has already existed");
				new_variable <function>(fname, "function", f);
			}

			inline const function& get_function_by_resolved_name(const std::string& resolved_func_name)const
			{
				const context* vc = this;
				while (vc != nullptr)
				{
					auto iter = vc->functions.find(resolved_func_name);
					if (iter != vc->functions.end())
						return iter->second;
					else
						vc = vc->pfather;
				}
				throw_error("do not have this function");
			}

			inline std::optional<const function*> find_function_by_resolved_name(const std::string& resolved_func_name)const
			{
				const context* vc = this;
				while (vc != nullptr)
				{
					auto iter = vc->functions.find(resolved_func_name);
					if (iter != vc->functions.end())
						return &iter->second;
					else
						vc = vc->pfather;
				}
				return std::nullopt;
			}

			inline const function& get_function(const std::string& func_name, const std::vector<std::string>& arg_types)const
			{
				const function* f = nullptr;
				function buff_f;
				buff_f.function_name = func_name;
				buff_f.arguments_type_names = arg_types;
				auto fname = backend::resolve_function_name(buff_f);

				auto opt = find_function_by_resolved_name(fname);
				if (opt)
				{
					f = opt.value();
				}
				else
				{
					auto opt2 = find_function_by_resolved_name(func_name);
					if (opt2)
						f = opt2.value();
					else
						throw_error("do not have this function");
				}
				if (f == nullptr)
					throw_error("do not have this function");
				if (f->is_va_arg == false)
				{
					if (f->arguments_type_names.size() != arg_types.size())
						throw_error("error function call arguments");
					for (int i = 0; i < arg_types.size(); i++)
					{
						if (f->arguments_type_names[i] != arg_types[i])
							throw_error("error function call arguments");
					}
				}
				return *f;
			}

		private:
			std::unordered_map<std::string, variable> variables;
			std::unordered_map<std::string, backend::function> functions;
			std::unordered_map<std::string, type_information> types;
			context* pfather;
			int unname_count;
		};

		template<typename T>
		inline static type_information make_type_information(const std::string& type_name)
		{
			return type_information{ type_name ,
				[]() {return new T(); },
				[](void* p) {delete reinterpret_cast<T*>(p); } ,
				[](void* dest,void* src) {*reinterpret_cast<T*>(dest) = *reinterpret_cast<T*>(src); } };
		}

		struct key_word
		{
			std::function<variable(backend&, context&, ast_node*)> run_func;
		};

		struct function
		{
			std::string function_name;
			std::vector<std::string> arguments_type_names;
			std::function<variable(context&, const std::vector<variable>&)> run_func;
			bool is_va_arg = false;
		};

		inline backend()
			:global_context(nullptr)
		{
			global_context.add_type(type_information{ "void" ,[]() {return nullptr; },[](void*) {},[](void*,void*) {} });
			global_context.add_type(make_type_information<function>("function"));
			global_context.add_type(make_type_information<char>("char"));
			global_context.add_type(make_type_information<int>("int"));
			global_context.add_type(make_type_information<float>("float"));
			global_context.add_type(make_type_information<std::string>("string"));

			global_context.add_function(function{ "eval",{},[](context&, const std::vector<variable>&)->variable {return variable{ "void",nullptr }; } ,true });
		}

		inline ~backend()
		{

		}

		inline static std::string resolve_function_name(const function& f)
		{
			std::string re = f.function_name;
			if (f.is_va_arg == false)
			{
				for (auto& i : f.arguments_type_names)
					re += "@" + i;
			}
			return re;
		}

		inline void add_key_word(const std::string& name, const key_word& k)
		{
			auto iter = key_words.find(name);
			if (iter != key_words.end())
				throw_error("key work has already existed");
			key_words.insert(make_pair(name, k));
		}

		inline variable evaluate(ast_node* p, context& vc)
		{
			if (!p)
			{
				throw_error("null ptr error");
			}
			else
			{
				if (p->type == content_type::null)
				{
					if (p->pchildren.size() != 0)
					{
						context nvc(&vc);

						const function* f = nullptr;

						if (p->pchildren[0]->type == content_type::null)
						{
							auto fvar = evaluate(p->pchildren[0], nvc);
							if (fvar.type_name != "function")
							{
								throw_error("can not evaluate this variable, it is not function");
							}
							f = reinterpret_cast<function*>(fvar.pcontent);
						}

						if (key_words.find(p->pchildren[0]->content) != key_words.end() && p->pchildren[0]->type == content_type::variable)
						{
							auto iter = key_words.find(p->pchildren[0]->content);
							return iter->second.run_func(*this, vc, p);
						}

						std::vector<variable> args;
						std::vector<std::string> arg_types;
						for (int i = 1; i < p->pchildren.size(); i++)
						{
							args.emplace_back(evaluate(p->pchildren[i], nvc));
							arg_types.emplace_back(args[args.size() - 1].type_name);
						}

						if (!f)
						{
							if (p->pchildren[0]->type != content_type::variable)
								throw_error("can not evaluate this thing");
							f = &(vc.get_function(p->pchildren[0]->content, arg_types));
						}
						else
						{
							if (f->is_va_arg == false)
							{
								if (f->arguments_type_names.size() != arg_types.size())
									throw_error("error function call arguments");
								for (int i = 0; i < arg_types.size(); i++)
								{
									if (f->arguments_type_names[i] != arg_types[i])
										throw_error("error function call arguments");
								}
							}
						}

						return f->run_func(vc, args);

					}
					else
					{
						return variable{ "void",nullptr };
					}
				}
				else if (p->type == content_type::variable)
				{
					return vc.find_variable(p->content);
				}
				else if (p->type == content_type::constant_character)
				{
					return vc.new_unnamed_variable<char>("char", p->content[0]);
				}
				else if (p->type == content_type::constant_decimal)
				{
					return vc.new_unnamed_variable<float>("float", std::stof(p->content));
				}
				else if (p->type == content_type::constant_integer)
				{
					return vc.new_unnamed_variable<int>("int", std::stoi(p->content));
				}
				else if (p->type == content_type::constant_string)
				{
					return vc.new_unnamed_variable<std::string>("string", p->content);
				}
			}
		}

		inline void run(ast_node* p)
		{
			for (auto i : p->pchildren)
				evaluate(i, global_context);
		}

		inline context& get_global_context()
		{
			return global_context;
		}

		inline const context& get_global_context()const
		{
			return global_context;
		}
	private:
		std::unordered_map<std::string, key_word> key_words;
		context global_context;
	};

	class interpreter
	{
	public:
		template<typename T>
		void add_type(const std::string& type_name)
		{
			mbackend.get_global_context().add_type(backend::make_type_information<T>(type_name));
		}
		void add_function(const std::string& func_name, const std::vector<std::string>& func_args_type, bool is_va_arg, const std::function<backend::variable(backend::context&, const std::vector<backend::variable>&)>& run_func)
		{
			mbackend.get_global_context().add_function(backend::function{ func_name,func_args_type,run_func,is_va_arg });
		}
		void add_key_word(const std::string& key_word_name, const std::function<backend::variable(backend&, backend::context&, ast_node*)>& func)
		{
			mbackend.add_key_word(key_word_name, backend::key_word{ func });
		}
		void run_from_file(const std::string& file_name)
		{
			std::string strbuff;
			std::string total_str;
			std::ifstream file(file_name);

			while (std::getline(file, strbuff))
			{
				total_str += strbuff + '\n';
			}
			mparser.parse(total_str);
			mbackend.run(mparser.get_ast_root());
		}

		void run_from_string(const std::string& str)
		{
			mparser.parse(str);
			mbackend.run(mparser.get_ast_root());
		}
	private:
		parser mparser;
		backend mbackend;
	};


	void add_core_content(interpreter& in)
	{
		in.add_key_word("def", [](backend& b, backend::context& vc, ast_node* p)->backend::variable {
			if (!p)
				throw_error("nullptr error");
			if (p->pchildren.size() < 3 ||
				p->pchildren[1]->type != content_type::variable ||
				p->pchildren[2]->type != content_type::variable)
				throw_error("error def call");
			auto type_name = p->pchildren[1]->content;
			auto var_name = p->pchildren[2]->content;
			if (vc.has_variable(var_name))
				throw_error("already has this variable");
			if (vc.find_type(type_name).has_value() == false)
				throw_error("do not have this type");


			std::vector<backend::variable> args;
			std::vector<std::string> arg_types;

			backend::context nvc(&vc);
			for (int i = 3; i < p->pchildren.size(); i++)
			{
				args.emplace_back(b.evaluate(p->pchildren[i], nvc));
				arg_types.emplace_back(args[args.size() - 1].type_name);
			}

			auto var = vc.get_function(type_name, arg_types).run_func(vc, args);
			return vc.move_existed_variable(var_name, var);
			});
		in.add_key_word("def_func", [](backend& b, backend::context& vc, ast_node* p)->backend::variable {
			if (!p)
				throw_error("nullptr error");
			if (p->pchildren.size() < 3 ||
				p->pchildren[1]->type != content_type::variable ||
				p->pchildren[p->pchildren.size() - 1]->type != content_type::null)
				throw_error("error def call_func");
			auto func_name = p->pchildren[1]->content;

			std::vector<std::string> arg_types;
			std::vector<std::string> arg_names;
			for (int i = 2; i < p->pchildren.size() - 1; i++)
			{
				//no support for default argument
				ast_node* parg = p->pchildren[i];
				if (parg->type != content_type::null ||
					parg->pchildren.size() != 2 ||
					parg->pchildren[0]->type != content_type::variable ||
					parg->pchildren[1]->type != content_type::variable)
					throw_error("error argument define");

				std::string type_name = parg->pchildren[0]->content;
				if (vc.find_type(type_name).has_value() == false)
					throw_error("do not have this type");
				arg_types.emplace_back(type_name);

				arg_names.emplace_back(parg->pchildren[1]->content);
			}

			ast_node* run_node = p->pchildren[p->pchildren.size() - 1];

			backend::function f;
			f.function_name = func_name;
			f.arguments_type_names = arg_types;
			f.is_va_arg = false;
			f.run_func = [&b, arg_names, run_node](backend::context& vc, const std::vector<backend::variable>& args)->backend::variable {
				backend::context nvc(&vc);
				if (args.size() != arg_names.size())
					throw_error("error function call");
				for (int i = 0; i < args.size(); i++)
				{
					const backend::type_information& ti = vc.get_type(args[i].type_name);
					void* pnv = ti.default_construction_func();
					ti.copy_func(pnv, args[i].pcontent);
					nvc.move_existed_variable(arg_names[i], backend::variable(ti.type_name, pnv));
				}
				return b.evaluate(run_node, nvc);
			};

			vc.add_function(f);

			return backend::variable{ "function",(backend::function*)&(vc.get_function(func_name,arg_types)) };
			});
		in.add_function("int", { "int" }, false, [](backend::context& vc, const std::vector<backend::variable>& args)->backend::variable {
			return backend::variable{ "int",new int(args[0].as<int>()) };
			});
		in.add_function("int", { }, false, [](backend::context& vc, const std::vector<backend::variable>& args)->backend::variable {
			return backend::variable{ "int",new int(0) };
			});
		in.add_function("float", { "float" }, false, [](backend::context& vc, const std::vector<backend::variable>& args)->backend::variable {
			return backend::variable{ "float",new float(args[0].as<float>()) };
			});
		in.add_function("float", { }, false, [](backend::context& vc, const std::vector<backend::variable>& args)->backend::variable {
			return backend::variable{ "float",new float(0.0f) };
			});
		in.add_function("char", { "char" }, false, [](backend::context& vc, const std::vector<backend::variable>& args)->backend::variable {
			return backend::variable{ "char",new char(args[0].as<char>()) };
			});
		in.add_function("char", { }, false, [](backend::context& vc, const std::vector<backend::variable>& args)->backend::variable {
			return backend::variable{ "char",new char('\0') };
			});
		in.add_function("string", { "string" }, false, [](backend::context& vc, const std::vector<backend::variable>& args)->backend::variable {
			return backend::variable{ "string",new std::string(args[0].as<std::string>()) };
			});
		in.add_function("string", { }, false, [](backend::context& vc, const std::vector<backend::variable>& args)->backend::variable {
			return backend::variable{ "string",new std::string() };
			});
		in.add_function("print", {}, true, [](backend::context& vc, const std::vector<backend::variable>& args)->backend::variable {
			for (auto& i : args)
			{
				const backend::function& func = vc.get_function("print", { i.type_name });
				if (func.is_va_arg)
					throw_error("no matched print function");
				func.run_func(vc, { i });
			}
			return backend::variable{ "void",nullptr };
			});
		in.add_function("read", {}, true, [](backend::context& vc, const std::vector<backend::variable>& args)->backend::variable {
			for (auto& i : args)
			{
				const backend::function& func = vc.get_function("read", { i.type_name });
				if (func.is_va_arg)
					throw_error("no matched print function");
				func.run_func(vc, { i });
			}
			return backend::variable{ "void",nullptr };
			});
		in.add_function("read", { "int" }, false, [](backend::context& vc, const std::vector<backend::variable>& args)->backend::variable {
			std::cin >> args[0].as<int>();
			return args[0];
			});
		in.add_function("print", { "int" }, false, [](backend::context& vc, const std::vector<backend::variable>& args)->backend::variable {
			std::cout << args[0].as<int>();
			return backend::variable{ "void",nullptr };
			});
		in.add_function("read", { "float" }, false, [](backend::context& vc, const std::vector<backend::variable>& args)->backend::variable {
			std::cin >> args[0].as<float>();
			return args[0];
			});
		in.add_function("print", { "float" }, false, [](backend::context& vc, const std::vector<backend::variable>& args)->backend::variable {
			std::cout << args[0].as<float>();
			return backend::variable{ "void",nullptr };
			});
		in.add_function("read", { "char" }, false, [](backend::context& vc, const std::vector<backend::variable>& args)->backend::variable {
			std::cin >> args[0].as<char>();
			return args[0];
			});
		in.add_function("print", { "char" }, false, [](backend::context& vc, const std::vector<backend::variable>& args)->backend::variable {
			std::cout << args[0].as<char>();
			return backend::variable{ "void",nullptr };
			});
		in.add_function("read", { "string" }, false, [](backend::context& vc, const std::vector<backend::variable>& args)->backend::variable {
			std::cin >> args[0].as<std::string>();
			return args[0];
			});
		in.add_function("print", { "string" }, false, [](backend::context& vc, const std::vector<backend::variable>& args)->backend::variable {
			std::cout << args[0].as<std::string>();
			return backend::variable{ "void",nullptr };
			});
	}
}