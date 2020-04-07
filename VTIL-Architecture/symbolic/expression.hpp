#pragma once
#include <vector>
#include <optional>
#include <functional>
#include <type_traits>
#include "variable.hpp"
#include "operators.hpp"

namespace vtil::symbolic
{
	struct expression;
	using symbol_set = std::set<unique_identifier>;
	using symbol_map = std::map<variable, expression>;
	using fn_exp_callback = std::function<void( expression& )>;
	using fn_const_exp_callback = std::function<void( const expression& )>;

	// Describes an expression tree.
	//
	struct expression
	{
		// If variable, the value of the expression.
		//
		std::optional<variable> value;

		// If result, list of operands and the operator description.
		//
		const operator_desc* fn;
		std::vector<expression> operands;

		// Set to true if the expression was already simplified by the simplifier.
		// This allows us to indicate that this expression cannot be simplified
		// any further and thus makes recursive simplification much more time
		// efficient when it's called from multiple points of the application.
		//
		bool is_simplest_form = false;
		auto& declare_simple() { is_simplest_form = true; return *this; }
		auto& declare_changed() { is_simplest_form = false; return *this; }

		// Default constructors.
		//
		expression() : fn( nullptr ) {}
		expression( const variable& a ) : value( a ), fn( nullptr ), is_simplest_form( true ) {}
		expression( const operator_desc* fn, const expression& a ) : operands( { a } ), fn( fn ) {}
		expression( const expression& a, const operator_desc* fn, const expression& b ) : operands( { a, b } ), fn( fn ) {}

		// Helpers to determine the type of the expression.
		//
		bool is_expression() const { return operands.size() && !value; }
		bool is_variable() const { return operands.empty() && value; }
		bool is_constant() const { return is_variable() && value->is_constant(); }
		bool is_valid() const { return is_variable() ? operands.empty() : fn && ( fn->is_unary ? 1 : 2 ) == operands.size(); }

		// Calls the callback provided for every expression that
		// is actually a boxed symbolic variable.
		//
		void enum_symbols( const fn_exp_callback& cb )
		{
			if ( is_variable() )
			{
				if ( value->is_symbolic() )
					cb( *this );
				return;
			}
			for ( auto& op : operands )
				op.enum_symbols( cb );
		}

		// Calls the callback provided for every expression that
		// is actually a boxed symbolic variable. [Const]
		//
		void enum_symbols( const fn_const_exp_callback& cb ) const
		{
			if ( is_variable() )
			{
				if ( value->is_symbolic() )
					cb( *this );
				return;
			}
			for ( auto& op : operands )
				op.enum_symbols( cb );
		}

		// Creates a set containing every unique symbol used in
		// this expression tree.
		//
		symbol_set enum_symbols() const
		{
			symbol_set tmp;
			enum_symbols( [ & ] ( auto& x ) { tmp.insert( x.value->uid ); } );
			return tmp;
		}

		// Returns whether the expression contains the given
		// symbolic variable in any size or not.
		//
		bool contains_symbol( const unique_identifier& uid ) const
		{
			if ( is_variable() )
				return value->uid == uid;
			for ( auto& operand : operands )
				if ( operand.contains_symbol( uid ) )
					return true;
			return false;
		}

		// Counts the number of unique symbols used in this
		// expression tree.
		//
		size_t count_symbols() const
		{
			return enum_symbols().size();
		}

		// Remaps every occurance of the symbol<uid> with the 
		// expression provided.
		//
		void remap_symbols( const symbol_map& sym_map )
		{
			enum_symbols( [ & ]( expression& v )
			{
				for ( auto& sym : sym_map )
				{
					if ( sym.first.uid == v.value->uid )
						v = sym.second;
				}
			} );
		}
		void remap_symbol( const unique_identifier& uid, const expression& as )
		{
			enum_symbols( [ & ] ( expression& v )
			{
				if ( v.value->uid == uid )
					v = as;
			} );
		}

		// Checks if the expression is normalized.
		//
		bool is_normalized() const
		{
			if ( is_variable() || fn->is_unary || fn->result_size == 0 )
				return true;
			uint8_t s0 = operands[ 0 ].size();
			uint8_t s1 = operands[ 1 ].size();
			return s0 == 0 || s1 == 0 || s0 == s1;
		}

		// Returns the size of the output value.
		//
		uint8_t size( bool real_size = false ) const
		{
			// If variable, return size as is.
			//
			if ( is_variable() )
				return value->calc_size( false );

			// Exceptional operators:
			//
			if ( fn->function == "__zx" ||
				 fn->function == "__sx" )
				return real_size ? operands[ 0 ].value->get() : operands[ 1 ].value->get();
			if ( fn->function == "__bcnt" ||
				 fn->function == "__bcntN" )
				return 1;

			// If unary operator or result size is first operand,
			// redirect to the first operand.
			//
			if ( fn->is_unary || fn->result_size == 0 )
				return operands[ 0 ].size( real_size );

			// Process according to the operator definition.
			//
			uint8_t s0 = operands[ 0 ].size( real_size );
			uint8_t s1 = operands[ 1 ].size( real_size );
			if ( fn->result_size == 1 )
				return std::max( s0, s1 );
			else
				return std::min( s0, s1 );
		}

		// Changes the size of the output value.
		//
		expression& resize( uint8_t size, bool sign_extend = false )
		{
			// Can't resize to <any size>
			//
			if ( size == 0 )
				return *this;

			// If variable, resize it:
			//
			if ( is_variable() )
			{
				if ( value->is_symbolic() )
				{
					if ( value->size == size ) 
						return *this;

					if ( value->size < size )
						*this = expression( *this, sign_extend ? find_opr( "__sx" ) : find_opr( "__zx" ), variable( size ) );
					else
						value->resize( size, sign_extend );
				}
				else
				{
					value->resize( size, sign_extend );
				}
				return *this;
			}
			// If result of an operator:
			//
			else if( is_expression() )
			{
				// If function is an extender, apply to the argument.
				//
				if ( fn->function == "__zx" ||
					 fn->function == "__sx" )
				{
					*this = operands[ 0 ];
					resize( size, sign_extend );
				}
				// If unary operator or result size is first operand,
				// redirect to the first operand.
				//
				else if ( fn->is_unary || fn->result_size == 0 )
				{
					operands[ 0 ].resize( size, !fn->is_bitwise );
				}
				// Otherwise, resize both.
				//
				else
				{
					// Cannot shrink in a simple way if rotate or shift right
					//
					if( fn->function == "rol" || fn->function == "ror" || fn->function == "shr" )
						fassert( size >= operands[ 0 ].size() );

					operands[ 0 ].resize( size, !fn->is_bitwise );
					operands[ 1 ].resize( size, !fn->is_bitwise );
				}

				// Declare that the expression was changed.
				//
				declare_changed();
			}
			return *this;
		}

		// Returns an arbitrary value that represents the "complexity"
		// of the expression. It's used for the simplification algorithm.
		//
		size_t complexity() const
		{
			// If it's a variable:
			//
			if ( is_variable() )
				return value->is_constant() ? 0 : 1;

			// Exceptional operators:
			//
			if ( fn->function == "__bcntN" ||
				 fn->function == "__zx" ||
				 fn->function == "__sx" )
				return operands[ 0 ].complexity();
			if ( fn->function == "__bcnt" ||
				 fn->function == "__bcntN" ||
				 fn->function == "__bmask" )
				return 0;

			// Ideally we want less operations on symbolic variables, 
			// so create an exponentially increasing cost.
			//
			if ( fn->is_unary )
				return operands[ 0 ].complexity() << 1;
			else
				return ( operands[ 0 ].complexity() + operands[ 1 ].complexity() ) << 1;
		}

		// Depth of the operation tree.
		//
		size_t depth() const
		{
			// If variable, return 1.
			//
			if ( is_variable() )
				return 0;

			// Exceptional operators:
			//
			if ( fn->function == "__bcntN" ||
				 fn->function == "__zx" ||
				 fn->function == "__sx" )
				return operands[ 0 ].depth();
			if ( fn->function == "__bcnt" ||
				 fn->function == "__bcntN" ||
				 fn->function == "__bmask" )
				return 0;

			// For each operand, recurse and sum.
			//
			size_t out = 1;
			for ( auto& subexp : operands )
				out += subexp.depth();
			return out;
		}

		// Tries to evaluate the numeric value of a symbolic expression.
		//
		std::optional<variable> evaluate() const
		{
			// If expression is a boxed variable, return as is.
			//
			if ( is_variable() )
				return is_constant() ? value : std::nullopt;

			// Handle resizing.
			//
			if ( fn->function == "__zx" )
			{
				auto res = operands[ 0 ].evaluate();
				if ( res )
					res->resize( operands[ 1 ].value->get(), false );
				return res;
			}
			else if ( fn->function == "__sx" )
			{
				auto res = operands[ 0 ].evaluate();
				if ( res )
					res->resize( operands[ 1 ].value->get(), true );
				return res;
			}

			auto operands_n = operands;
			size_t ns = size();

			// ------- Unary operators ------- //
			if ( fn->function == "__bcnt" )
				return variable{ operands_n[ 0 ].size() * 8, ns };
			else if ( fn->function == "__bmask" )
				return variable{ ~0ull >> ( 64 - operands_n[ 0 ].size() * 8 ), ns };

			variable o1;
			if ( auto r = operands_n[ 0 ].evaluate() ) o1 = r.value();
			else return {};

			if ( fn->function == "neg" )
				return variable{ -o1.get<true>(), ns };
			else if ( fn->function == "not" )
				return variable{ ~o1.get(), ns };

			// ------- Binary operators ------- //
			if ( fn->function == "__bcntN" )
				return variable{ uint8_t( ( o1.get() ) % ( operands_n[ 1 ].size() * 8 ) ), operands_n[ 0 ].size() };

			variable o2;
			if ( auto r = operands_n[ 1 ].evaluate() ) o2 = r.value();
			else return {};

			if ( fn->function == "or" )
				return variable{ o1.get() | o2.get(), ns };
			else if ( fn->function == "and" )
				return variable{ o1.get() & o2.get(), ns };
			else if ( fn->function == "xor" )
				return variable{ o1.get() ^ o2.get(), ns };
			else if ( fn->function == "shr" )
				return ( ns && o2.get() >= ( ns * 8 ) ) ? variable{ 0, ns } : variable{ o1.get( ns ) >> o2.get(), ns };
			else if ( fn->function == "shl" )
				return ( ns && o2.get() >= ( ns * 8 ) ) ? variable{ 0, ns } : variable{ o1.get( ns ) << o2.get(), ns };
			else if ( fn->function == "ror" )
				return variable{ ( o1.get( ns ) >> o2.get() ) | ( o1.get( ns ) << ( o1.size * 8 - o2.get() ) ), ns };
			else if ( fn->function == "rol" )
				return variable{ ( o1.get( ns ) << o2.get() ) | ( o1.get( ns ) >> ( o1.size * 8 - o2.get() ) ), ns };
			else if ( fn->function == "add" )
				return variable{ o1.get<true>() + o2.get<true>(), ns };
			else if ( fn->function == "sub" )
				return variable{ o1.get<true>() - o2.get<true>(), ns };
			
			// Other operators should not reach here.
			return {};
		}

		// Conversion to human readable format.
		//
		std::string to_string() const
		{
			// If variable redirect to it's own ::to_string.
			//
			if ( is_variable() )
				return value->to_string();
			fassert( fn );
			
			// If unary function:
			//
			if ( fn->is_unary )
			{
				fassert( operands.size() == 1 );
				return fn->symbol.size() 
					? fn->symbol + operands[ 0 ].to_string() 
					: fn->function + "(" + operands[ 0 ].to_string() + ")";
			}
			// If binary function:
			//
			fassert( operands.size() == 2 );
			return fn->symbol.size()
				? "(" + operands[ 0 ].to_string() + fn->symbol + operands[ 1 ].to_string() + ")"
				: fn->function + "(" + operands[ 0 ].to_string() + ", " + operands[ 1 ].to_string() + ")";
		}

		// Basic comparison operators.
		//
		bool operator==( const expression& o ) const 
		{
			if ( is_expression() && ( fn->function == "__zx" || fn->function == "__sx" ) )
				return o == operands[ 0 ];
			else if ( o.is_variable() )
				return is_variable() && value == o.value;
			else
				return is_expression() && fn == o.fn && operands == o.operands;
		}
		bool operator!=( const expression& o ) const { return !operator==( o ); }
		bool operator<( const expression& o ) const { return !operator==( o ) && to_string() < o.to_string(); }

		// Convinience wrapper for operand access.
		// - Use the .operands container manually when changing
		//   any operands and clear the simplest form hint.
		//
		const expression& operator[]( size_t i ) const { return operands[ i ]; }

		// Convinience wrappers around common operations.
		//
		expression operator+() const { return expression( *this ); }
		expression operator~() const { return expression( find_opr( "not" ), *this ); }
		expression operator-() const { return expression( find_opr( "neg" ), *this ); }
		template<typename T> expression ror( T y ) const { return expression( *this, find_opr( "ror" ), expression{ y } ); }
		template<typename T> expression rol( T y ) const { return expression( *this, find_opr( "rol" ), expression{ y } ); }
	};

	template<typename T> static expression operator+( const expression& x, T y ) { return { x, find_opr( "add" ), expression{ y } }; }
	template<typename T> static expression operator-( const expression& x, T y ) { return { x, find_opr( "sub" ), expression{ y } }; }
	template<typename T> static expression operator|( const expression& x, T y ) { return { x, find_opr( "or" ), expression{ y } }; }
	template<typename T> static expression operator&( const expression& x, T y ) { return { x, find_opr( "and" ), expression{ y } }; }
	template<typename T> static expression operator^( const expression& x, T y ) { return { x, find_opr( "xor" ), expression{ y } }; }
	template<typename T> static expression operator>>( const expression& x, T y ) { return { x, find_opr( "shr" ), expression{ y } }; }
	template<typename T> static expression operator<<( const expression& x, T y ) { return { x, find_opr( "shl" ), expression{ y } }; }

	template<typename T, std::enable_if_t<!std::is_same_v<std::remove_cvref_t<T>, expression>, int> = 0> 
	static expression operator+( T x, const expression& y ) { return expression{ x } + y; }
	template<typename T, std::enable_if_t<!std::is_same_v<std::remove_cvref_t<T>, expression>, int> = 0> 
	static expression operator-( T x, const expression& y ) { return expression{ x } - y; }
	template<typename T, std::enable_if_t<!std::is_same_v<std::remove_cvref_t<T>, expression>, int> = 0> 
	static expression operator|( T x, const expression& y ) { return expression{ x } | y; }
	template<typename T, std::enable_if_t<!std::is_same_v<std::remove_cvref_t<T>, expression>, int> = 0> 
	static expression operator&( T x, const expression& y ) { return expression{ x } & y; }
	template<typename T, std::enable_if_t<!std::is_same_v<std::remove_cvref_t<T>, expression>, int> = 0> 
	static expression operator^( T x, const expression& y ) { return expression{ x } ^ y; }
	template<typename T, std::enable_if_t<!std::is_same_v<std::remove_cvref_t<T>, expression>, int> = 0> 
	static expression operator>>( T x, const expression& y ) { return expression{ x } >> y; }
	template<typename T, std::enable_if_t<!std::is_same_v<std::remove_cvref_t<T>, expression>, int> = 0> 
	static expression operator<<( T x, const expression& y ) { return expression{ x } << y; }
};