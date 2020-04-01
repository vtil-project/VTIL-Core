#pragma once
#include <map>
#include <atomic>
#include <mutex>
#include <tuple>
#include <type_traits>
#include "instruction.hpp"

namespace vtil
{
	// Forward declaration of basic block.
	//
	struct basic_block;

	// Descriptor for any routine that is being translated.
	//
	struct routine
	{
		// Mutex guarding the whole structure, if a member is 
		// not explicitly marked, this mutex should be acquired
		// before accesing it.
		//
		std::mutex mutex;

		// Index of the last temporary register used.
		//
		std::atomic<int32_t> temporary_index_counter = -1;

		// Cache of explored blocks, mapping virtual instruction
		// pointer to the basic block structure.
		//
		std::map<vip_t, basic_block*> explored_blocks;

		// Reference to the first block, entry point.
		// - Can be accessed without acquiring the mutex as it
		//   will be assigned strictly once.
		//
		basic_block* entry_point = nullptr;

		// Invokes the enumerator passed for each basic block 
		// this routine contains.
		//
		template<typename enumerator_function>
		void for_each( const enumerator_function& enumerator ) const
		{
			for ( auto& block : explored_blocks )
				enumerator( const_cast<basic_block*>(block.second) );
		}
	};
};