#pragma once
#include <vtil/arch>

#include <vtil/optimizer>// replace with interface.hpp

// put in .cpp
#include <vtil/query>

namespace vtil::optimizer
{
	// <TODO>
	//
	struct bblock_rewriting_pass : pass_interface<>
	{
		size_t pass( basic_block* blk, bool xblock = false ) override 
		{
			size_t counter = 0;

			return counter;
		}
	};
};