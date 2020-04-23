#include "routine.hpp"
#include "basic_block.hpp"

namespace vtil
{
	// Routine structures free all basic blocks they own upon their destruction.
	//
	routine::~routine()
	{
		for ( auto [vip, block] : explored_blocks )
			delete block;
	}
};
