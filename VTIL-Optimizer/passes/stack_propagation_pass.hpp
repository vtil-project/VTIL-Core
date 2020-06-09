#pragma once
#include <vtil/arch>
#include "../interface.hpp"

namespace vtil::optimizer
{
	// Attempts to resolve all loads from stack where the value can be 
	// determined during compile time.
	//
	struct stack_propagation_pass : pass_interface<true>
	{
		size_t pass( basic_block* blk, bool xblock = false ) override;
	};
};