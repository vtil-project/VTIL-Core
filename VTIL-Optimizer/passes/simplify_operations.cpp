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
#include "normalize_stack.hpp"
#include <vector>
#include <vtil/query>
#include <vtil/symex>

namespace vtil::optimizer
{
	size_t simplify_operations( basic_block* block )
	{
		cached_tracer tracer;
		size_t counter = 0;

		/*// => Begin a foward iterating query.
		//
		query::create( block->begin(), +1 )

			// >> Skip volatile instructions.
			.where( [ ] ( instruction& ins ) { return !ins.is_volatile(); } )
			
			// | Filter to instructions with symbolic operators:
			.where( [ ] ( instruction& ins ) { return ins.base->symbolic_operator != math::operator_id::invalid; } )

			// := Project back to iterator type.
			.unproject()
			
			// @ For each:
			.for_each( [ & ] ( const il_iterator& it )
			{
				using namespace logger;

				register_desc reg = {};
				for ( int i = 0; i < it->base->operand_count(); i++ )
				{
					if ( it->base->operand_types[ i ] >= operand_type::write )
					{
						if ( !reg.is_valid() )
							reg = it->operands[ i ].reg();
						else
							return;
					}
				}

				// Trace the result.
				//
				auto at = std::next( it );
				auto e1 = tracer( { at, reg } );
				log<CON_RED>( "<= %s\n", e1 );
				
				// Try to avoid repeating calculations in the expression:
				//
				e1.transform( [ & ] ( symbolic::expression& exp )
				{
					// Skip if top-level node or is a constant.
					//
					if ( &exp == &e1 || exp.is_constant() )
						return;

					// For each cache entry:
					//
					for ( auto& [var, val] : tracer.cache )
					{
						// Skip if memory variable or value is not identical.
						//
						if ( var.is_memory() || !val->clone().resize( exp.size() ).is_identical( exp ) )
							continue;

						// Resize register according to minimum size.
						//
						auto reg = var.reg();
						reg.bit_count = std::min( reg.bit_count, exp.size() );
						symbolic::variable sreg = { reg };

						// Determine if the variable is still alive, skip if not.
						//
						bool is_alive = !reg.is_volatile();
						for ( auto it = var.at; !it.is_end() && is_alive && it != at; it++ )
							is_alive &= !sreg.written_by( it, &tracer );
						if ( !is_alive )
							continue;

						// If we passed all checks, replace expression and break.
						//
						exp = var.to_expression().resize( exp.size() );
						break;
					}
				}, false );

				// Pack the result.
				//
				symbolic::variable::pack_all( e1 );
				log<CON_GRN>( "=> %s\n", e1 );

				++counter;
			});*/

		return counter;
	}
	size_t simplify_operations( routine* rtn )
	{
		size_t counter = 0;
		rtn->for_each( [ & ] ( auto block ) { counter += simplify_operations( block ); } );
		return counter;
	}
};