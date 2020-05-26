#pragma once
#include <vtil/symex>
#include "../symex/variable.hpp"

namespace vtil
{
	struct tracer
	{
		// Traces a variable across the basic block it belongs to and generates a symbolic expression 
		// that describes it's value at the bound point. The provided variable should not contain a 
		// pointer with out-of-block expressions.
		//
		virtual symbolic::expression trace( symbolic::variable lookup );

		// Traces a variable across the entire routine and tries to generates a symbolic expression
		// for it at the specified point of the block.
		//
		virtual symbolic::expression rtrace( symbolic::variable lookup );

		// Wrappers around the functions above that return expressions with the registers packed.
		//
		symbolic::expression trace_p( symbolic::variable lookup ) { return symbolic::variable::pack_all( trace( std::move( lookup ) ) ); }
		symbolic::expression rtrace_p( symbolic::variable lookup ) { return symbolic::variable::pack_all( rtrace( std::move( lookup ) ) ); }

		// Operator() wraps trace_p and [] wraps rtrace_p.
		//
		auto operator()( symbolic::variable lookup ) { return trace_p( std::move( lookup ) ); }
		auto operator[]( symbolic::variable lookup ) { return rtrace_p( std::move( lookup ) ); }
	};
};