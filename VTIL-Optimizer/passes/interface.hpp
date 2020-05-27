#pragma once
#include <vtil/arch>
#include <initializer_list>
#include <numeric>

namespace vtil::optimizer
{
	// Declares a generic pass interface that any optimization pass implements.
	// - Passes should be always default constructable.
	//
	struct pass_interface
	{
		// Passes a single basic block through the optimizer, xblock will be set to true
		// if cross-block exploration is allowed.
		//
		virtual size_t pass( basic_block* blk, bool xblock = false ) = 0;

		// Passes every block through the optimizer with block refrences freely explorable,
		// returns the number of instances where this optimization was applied.
		//
		virtual size_t xpass( routine* rtn ) 
		{ 
			size_t n = 0; 
			rtn->for_each( [ & ] ( auto* blk ) { n += pass( blk, true ); } ); 
			return n; 
		}
	};

	// Passes through each optimizer provided and returns the total number of optimizations applied.
	//
	template<typename... Tx>
	struct combine_pass;
	template<typename T>
	struct combine_pass<T> : T {};
	template<typename T1, typename... Tx>
	struct combine_pass<T1, Tx...> : pass_interface
	{
		T1 t1 = {};
		combine_pass<Tx...> t2 = {};
		size_t pass( basic_block* blk, bool xblock = false ) override { return t1.pass( blk, xblock ) + t2.pass( blk, xblock ); }
		size_t xpass( routine* rtn ) override { return t1.xpass( rtn ) + t2.xpass( rtn ); }
	};

	// Passes through each optimizer provided until the passes do not change the block.
	//
	template<typename... Tx>
	struct exhaustive_pass : combine_pass<Tx...>
	{
		// Simple looping until pass returns 0.
		//
		size_t pass( basic_block* blk, bool xblock = false ) override 
		{ 
			size_t cnt = combine_pass<Tx...>::pass( blk, xblock );
			return cnt ? cnt + exhaustive_pass::pass( blk, xblock ) : 0;
		}
		size_t xpass( routine* rtn ) override
		{
			size_t cnt = combine_pass<Tx...>::pass( rtn );
			return cnt ? cnt + exhaustive_pass::pass( rtn ) : 0;
		}
	};
};