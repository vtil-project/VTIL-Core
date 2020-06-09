#pragma once
#include <vtil/arch>
#include "../interface.hpp"

namespace vtil::optimizer
{
	// Attempts to forward any movs to the actual uses of them where possible.
	//
	struct mov_propagation_pass : pass_interface<true>
	{
		size_t pass( basic_block* blk, bool xblock = false ) override;
	};
};