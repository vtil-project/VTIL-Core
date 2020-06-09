#pragma once
#include <vtil/arch>
#include "../interface.hpp"

namespace vtil::optimizer
{
	// Tries to statically resolve each indirect reference to stack pointer and substituting
	// the base register of the memory operation with the stack pointer.
	//
	struct istack_ref_substitution_pass : pass_interface<>
	{
		size_t pass( basic_block* blk, bool xblock = false ) override;
	};
};