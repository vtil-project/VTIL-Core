// Copyright (c) 2020 Can Boluk and contributors of the VTIL Project
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. Neither the name of mosquitto nor the names of its
//    contributors may be used to endorse or promote products derived from
//    this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
#include "fast_propagation_pass.hpp"
#include "fast_dead_code_elimination_pass.hpp"
#include <vtil/query>
#include "../common/auxiliaries.hpp"

namespace vtil::optimizer
{
	size_t fast_propagation_pass::pass( basic_block *blk, bool xblock )
	{
		size_t counter = 0;

		std::unordered_map<register_id, operand> reg_cache;
		std::unordered_map<std::pair<int64_t, uint64_t>, operand, hasher<>> sp_cache;
		for ( auto it = blk->begin(); !it.is_end(); ++it )
		{
			auto& ins = *it;

			// Check register reads and propagate if necessary.
			//
			if ( !ins.is_volatile() )
			{
				for ( auto[op, type] : ins.enum_operands())
				{
					if ( !op.is_register())
						continue;

					if ( type >= operand_type::write )
						continue;

					auto &reg = op.reg();
					if ( auto c_it = reg_cache.find( register_id( reg )); c_it != reg_cache.end())
					{
						const auto &new_op = c_it->second;

						// Check for operand validity.
						//
						if ( op.bit_count() != new_op.bit_count())
							continue;

						if ( type == operand_type::read_reg )
							if ( !new_op.is_register())
								continue;

						// Replace.
						//
						op = new_op;
						++counter;
					}
				}
			}

			// Do we store to memory?
			//
			if ( *ins.base == ins::str )
			{
				const auto& to_store = ins.operands[ 2 ];

				const auto [reg, loc] = ins.memory_location();
				if ( !reg.is_stack_pointer() )
					sp_cache.clear();

				// Emplace new store.
				sp_cache[{ loc, ins.access_size() }] = to_store;

				// Continue.
				continue;
			}

			// If we load an instruction, look up in cache. If we can propagate, do so.
			//
			if ( *ins.base == ins::ldd && !ins.is_volatile() )
			{
				const auto [reg, loc] = ins.memory_location();
				if ( reg.is_stack_pointer() )
				{
					if (auto n_it = sp_cache.find( { loc, ins.access_size() } ); n_it != sp_cache.end())
					{
						// Found a match? Replace instruction with mov.

						ins.base = &ins::mov;
						ins.operands = { ins.operands[ 0 ], n_it->second };
						++counter;
					}
				}

				// I have no idea why this is needed. The code below it should handle this but ?????
				//

				reg_cache.erase( register_id( ins.operands[ 0 ].reg() ) );
				if ( ins.operands[ 0 ].reg().is_stack_pointer() )
					sp_cache.clear();
				continue;
			}

			// Do we manipulate a register? If so, flush cache.
			//
			for (auto [op, type] : ins.enum_operands())
			{
				if (!op.is_register())
					continue;

				if (type >= operand_type::write)
				{
					if ( *ins.base == ins::mov )
						reg_cache[ register_id(op.reg()) ] = ins.operands[ 1 ];
					else
						reg_cache.erase( register_id(op.reg()) );

					if ( op.reg().is_stack_pointer() )
						sp_cache.clear();

					break;
				}
			}
		}

		return counter;
	}
}