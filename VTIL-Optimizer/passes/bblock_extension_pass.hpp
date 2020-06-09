#pragma once
#include <vtil/arch>
#include "../interface.hpp"

namespace vtil::optimizer
{
	// Attempts to merge multiple basic blocks into a single extended basic block.
	//
	struct bblock_extension_pass : pass_interface<true>
	{
		// List of blocks we have already visited, refreshed per xpass call.
		//
		std::set<basic_block*> visit_list;

		size_t pass( basic_block* blk, bool xblock = false ) override;
		size_t xpass( routine* rtn ) override;
	};
};