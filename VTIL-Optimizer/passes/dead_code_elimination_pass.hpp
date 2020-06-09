#pragma once
#include <vtil/arch>
#include "../interface.hpp"

namespace vtil::optimizer
{
	// <TODO>
	//
	struct dead_code_elimination_pass : pass_interface<true>
	{
		size_t pass( basic_block* blk, bool xblock = false ) override;
	};
};