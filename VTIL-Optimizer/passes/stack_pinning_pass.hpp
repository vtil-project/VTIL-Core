#pragma once
#include <vtil/arch>
#include "../interface.hpp"

namespace vtil::optimizer
{
	// Attempts to merge the value of REG_SP accross the block.
	//
	struct stack_pinning_pass : pass_interface<>
	{
		size_t pass( basic_block* blk, bool xblock = false ) override;
	};
};