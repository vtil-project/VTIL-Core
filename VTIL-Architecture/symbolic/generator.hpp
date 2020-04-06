#pragma once
#define SYMEX_EVALTIME_SIMPLIFY 1
#include <optional>
#include <iterator>
#include <functional>
#include <algorithm>
#include "variable.hpp"
#include "expression.hpp"
#include "simplifier.hpp"
#include "..\query\view.hpp"
#include "..\routine\instruction.hpp"
#include "..\routine\basic_block.hpp"

// Symbolic expression generator is essentialy the core of almost every optimization
// pass since it is used to create simplified equivalents for the given
// variable, which can be easily created from and cast back to any register 
// descriptor, view, or a memory pointer including external memory.
//
namespace vtil::symbolic
{
	// Generates a simplified expression for the given interator-bound variable
	// according to the instruction stream in the basic block, and any block that
	// jumps to it if recurse flag is set.
	//
	// - Adjust-RSP should be set if the caller wishes to receive
	//   real stack pointers as opposed to normalized ones such
	//   as the operands of STR and LDR where the memory offset 
	//   behaves indepdentent to the the stack pointer itself.
	//
	// - Handles branching and loops internally.
	//
	template<bool verbose = false>
	static expression generate( const variable& lookup,
								bool adjust_rsp = true,
								bool recurse = false,
								std::map<std::pair<const basic_block*, const basic_block*>, uint32_t> visited = {} )
	{
		// If we're not tracing a register or a memory value, return as is.
		//
		if ( !lookup.is_register() && !lookup.is_memory() )
			return { lookup };

		// If we are tracing a control register return the symbol as is.
		//
		if ( lookup.is_register() )
		{
			register_view rw = lookup.get_reg();
			if ( rw.base.maps_to >= X86_REG_VCR0 )
				return { lookup };
		}

		// Resolve query offset, size and iterator.
		//
		int32_t query_offset = lookup.is_register() ? lookup.get_reg().offset : 0;
		uint8_t query_size = lookup.size;
		fassert( query_size != 0 );

		// Log the beginning of the trace if verbose.
		//
		if constexpr ( verbose )
		{
			io::log( "=> Tracing %s", lookup.to_string() );
			io::log_padding++; io::log( "\n" );
		}

		// Craete the base query.
		//
		auto query_base = query::create( lookup.uid.origin, -1 ).unproject();
		expression pointer_exp = {};
		uint8_t current_size;
		int64_t current_offset;

		// If looking up register value:
		//
		if ( lookup.is_register() )
		{
			// | Filter to instructions that write to the register we're trying to resolve.
			query_base
				.where( [ & ] ( const ilstream_const_iterator& it ) { return it->writes_to( lookup.get_reg() ); } );
		}
		else
		{
			query_base
				// | Filter to instructions that write to memory.
				.where( [ ] ( const ilstream_const_iterator& it ) { return it->base->writes_memory(); } )

				// | Filter to instructions that write over our pointer.
				.where( [ & ] ( const ilstream_const_iterator& it )
				{
					auto [mem_base, mem_off] = it->get_mem_loc();

					// Check if both are reading from the same stack instance to optimize
					// the amount of time this lookup takes by avoiding another recursive call.
					//
					if ( mem_base == X86_REG_RSP &&
						 lookup.uid.get_mem().first == X86_REG_RSP &&
						 lookup.uid.memory_base_idx == it->sp_index )
					{
						// Offset is equivalent to the delta of their offset operands.
						//
						current_offset = mem_off - lookup.uid.get_mem().second;

						// Log write resolved if verbose.
						//
						if constexpr ( verbose )
							io::log<CON_RED>( "Write resolved to [@+%s]\n", format::hex( current_offset ) );
					}
					else
					{
						// If pointer expression generation was deferred, generate it now.
						//
						if ( !pointer_exp.is_valid() )
						{
							pointer_exp = generate<false>( { { lookup.uid.get_mem().first, lookup.uid.origin }, 8 }, true, false, {} ) + lookup.uid.get_mem().second;
							
							// Log pointer resolved if verbose.
							//
							if constexpr ( verbose )
								io::log<CON_GRN>( "Pointer resolved to [=%s]\n", pointer_exp.to_string() );
						}

						// Try to simplify the expression for [dst-lookup].
						//
						auto offset_exp = simplify( generate<false>( { { it, it->base->memory_operand_index }, 8 }, false, false, {} ) + mem_off - pointer_exp );

						// Log write resolved if verbose.
						//
						if constexpr ( verbose )
							io::log<CON_RED>( "Write resolved to [@+%s]\n", offset_exp.to_string() );

						// If it does not evaluate to a constant value, skip.
						//
						auto offset = offset_exp.evaluate();
						if ( !offset.has_value() || !offset->is_constant() )
							return false;

						// Offset is equivalent to the evaluated constant.
						//
						current_offset = offset->get<true>();
					}

					// Apply simple boundary check.
					//
					current_size = it->access_size();
					return -current_size < current_offset && current_offset < lookup.size;
				} );
		}

		// Define our query's main logic.
		//
		const auto to_result = [ & ] ( ilstream_const_iterator it ) -> expression
		{
			auto gen = [ & ] ( const variable& var ) { return generate<verbose>( var, adjust_rsp, recurse, visited ); };

			// If we are looking up a stack value:
			//
			if ( lookup.is_memory() )
			{
				// If an unknown/non-representable operation is being executed on 
				// the operand we're tracing, fail the trace.
				//
				if ( it->base != &ins::str )
					return variable( lookup ).bind( it );

				// If size and offset match: 
				//
				if ( query_offset == current_offset &&
					 query_size == current_size )
				{
					// Generate symbolic variable for the result.
					//
					return gen( { it, 2 } );
				}
			}
			// Else, if we are looking up a register value:
			//
			else
			{
				// If an unknown/non-representable operation is being executed on 
				// the operand we're tracing, fail the trace.
				//
				if ( it->base != &ins::mov && it->base != &ins::ldd && it->base->symbolic_operator.empty() )
					return variable( lookup ).bind( it );

				// Generic check for whether the symbol offset/size matches or not.
				// Will work as every instruction above writes to operand 1.
				//
				current_size = it->operands[ 0 ].reg.size;
				current_offset = it->operands[ 0 ].reg.offset;
				fassert( it->operands[ 0 ].is_register() );
				if ( query_offset == current_offset &&
					 query_size == current_size )
				{
					// If result is an immediate or simply another register:
					//
					if ( it->base == &ins::mov )
					{
						// Generate symbolic variable for the result.
						//
						return gen( { it, 1 } );
					}
					// If result is simply being loaded from external memory:
					//
					else if ( it->base == &ins::ldd )
					{
						// Generate symbolic variable for the result.
						//
						return gen( { it, -1 } );
					}
					// If it's the result of a symbolic operator:
					//
					else if ( !it->base->symbolic_operator.empty() )
					{
						const operator_desc* opr = find_opr( it->base->symbolic_operator );

						// OP1 = F(OP1)
						//
						if ( it->operands.size() == 1 )
						{
							fassert( opr->is_unary );

							// Resolve the value of OP1 prior to this instruction,
							// fail if recursive call fails.
							//
							expression op1e = gen( { it, 0 } );
							if ( !op1e.is_valid() )
								return variable( lookup ).bind( it );

							// Describe the operation.
							//
#if SYMEX_EVALTIME_SIMPLIFY
							return simplify( expression( opr, op1e ) );
#else
							return expression( opr, op1e );
#endif
						}
						// OP1 = F(OP1, OP2)
						//
						else if ( it->operands.size() == 2 )
						{
							fassert( !opr->is_unary );

							// Resolve the value of OP1 and OP2 prior to this 
							// instruction, fail if recursive call fails.
							//
							expression op1e = gen( { it, 0 } );
							if ( !op1e.is_valid() )
								return variable( lookup ).bind( it );
							expression op2e = gen( { it, 1 } );
							if ( !op2e.is_valid() )
								return variable( lookup ).bind( it );

							// Describe the operation.
							//
#if SYMEX_EVALTIME_SIMPLIFY
							return simplify( expression( op1e, opr, op2e ) );
#else
							return expression( op1e, opr, op2e );
#endif
						}
					}
					unreachable();
				}
			}

			/////////////////////////////////////////////
			// >>> Begin size / offset mismatch logic <<<
			/////////////////////////////////////////////

			// Helper to calculate the exact symbol we would have resolved.
			//
			const auto query_sub = [ & ] ( int64_t offset, uint8_t size )
			{
				// Create the symbolic identifier for the segment
				// and try to generate an expresion.
				//
				variable sub_lookup = lookup;
				sub_lookup.size = size;
				if ( lookup.is_register() )
					sub_lookup.uid.register_id->offset = offset, sub_lookup.uid.register_id->size = size;
				else if ( lookup.is_memory() )
					sub_lookup.uid.memory_id = { sub_lookup.uid.memory_id->first, sub_lookup.uid.memory_id->second + offset };
				else
					unreachable();
				sub_lookup.uid.origin = std::next( sub_lookup.uid.origin );
				sub_lookup.uid.refresh();
				expression exp = gen( sub_lookup );

				// If we failed, return as is.
				//
				if ( !exp.is_valid() )
					return exp;
				exp.resize( query_size, false );

				// Mask the result (and resize, abusing size == max(x.size, y.size))
				//
				exp = exp & variable( ~0ull >> ( 64 - size * 8 ), query_size );

				// If result belongs to low segment, shift left:
				//
				if ( offset > query_offset )
					exp = exp << variable( ( offset - query_offset ) * 8, query_size );

				// If result belongs to high segment, shift right:
				//
				else if ( offset < query_offset )
					exp = exp >> variable( ( query_offset - offset ) * 8, query_size );

				// Return the new expression.
				//
				return exp;
			};

			// Query current data we have with no mistmatch, fail if query fails.
			//
			expression result = query_sub( current_offset, current_size );
			if ( !result.is_valid() )
				return result;

			// If we have enough information to return as is do not query any other segments
			//
			if ( ( query_size + query_offset ) <= ( current_offset + current_size ) && query_offset >= current_offset )
				return result;

			// If the offsets match, we need to merge a high segment to the current result.
			//
			if ( current_offset == query_offset )
			{
				fassert( current_size < query_size );

				// Query high and merge it to the result.
				//
				expression high_res = query_sub( current_offset + current_size, query_size - current_size );
				if ( !high_res.is_valid() )
					return high_res;
				result = result | high_res;
			}
			// If offsets do not match, we need to 2 <= x <= 3 segments
			//
			else
			{
				// Query low (if relevant) and merge it to the result.
				//
				if ( query_offset < current_offset )
				{
					expression low_res = query_sub( query_offset, current_offset - query_offset );
					if ( !low_res.is_valid() )
						return low_res;
					result = result | low_res;
				}

				// Query high (if relevant) and merge it to the result.
				//
				int32_t off_query_end = query_offset + query_size;
				int32_t off_current_end = current_offset + current_size;
				if ( off_query_end > off_current_end )
				{
					expression high_res = query_sub( off_current_end, off_query_end - off_current_end );
					if ( !high_res.is_valid() )
						return high_res;
					result = result | high_res;
				}
			}

			// Simplify the result and return.
			//
#if SYMEX_EVALTIME_SIMPLIFY
			return simplify( result );
#else
			return result;
#endif
		};

		// Declare the output expression and the default expression.
		//
		expression result = {};
		variable default_result = variable( lookup ).unbind();
		int64_t default_result_offset = 0;

		// If looking up stack pointer and adjust flag is set:
		//
		if ( lookup.is_register() && lookup.get_reg() == X86_REG_RSP && adjust_rsp )
		{
			// Update the default result offset.
			//
			if ( !lookup.uid.origin.is_begin() )
				default_result_offset = std::prev( lookup.uid.origin )->sp_offset;
		}
		
		// If we could find a local result within the current block assign it as is.
		//
		if ( std::optional result_p = query_base.reproject( to_result ).first() )
		{
			result = result_p.value();
		}
		// If recursive scanning is allowed, try recursing into previous blocks.
		//
		else if ( recurse )
		{
			// Generate the list of iterators we could continue from.
			//
			std::vector it_list = query_base.query.iterator.recurse( false );

			// For each possible route:
			//
			for ( auto it : it_list )
			{
				// Create a local copy for the visited list for this path 
				// and increment the visit counter.
				//
				std::map visited_local = visited;
				uint32_t& visit_counter = visited_local[ { lookup.uid.origin.container, it.container } ];

				// If we've taken this route no more than once:
				//
				if ( visit_counter++ <= 1 )
				{
					// Generate a expression for the variable in the destination block.
					//
					expression exp = generate( variable( lookup ).bind( it ), adjust_rsp, recurse, visited_local );

					// Skip if we traced back to the lookup variable.
					//
					if ( is_equivalent( exp, default_result + default_result_offset ) )
					{
						// Log decision if verbose.
						//
						if constexpr ( verbose )
							io::log<CON_YLW>( "Candidate [%s] was rejected as it's self-referencing.\n", exp.to_string() );
						continue;
					}

					// If no result is set yet, assign the current expression:
					//
					if ( !result.is_valid() )
					{
						// Log decision if verbose.
						//
						if constexpr ( verbose )
							io::log<CON_GRN>( "Using [%s] as primary candidate.\n", exp.to_string() );
						result = exp;
					}
					// If previously set result is not equivalent to current expression
					// hint branch dependency and return default result:
					//
					else if( !is_equivalent( exp, result ) )
					{
						// Log decision if verbose.
						//
						if constexpr ( verbose )
							io::log<CON_RED>( "Cancelling query as candidate [%s] differs from previously set candidate.\n", exp.to_string() );
						result = {};
						default_result.uid.set_branch_dependency( true );
						default_result.uid.bind( lookup.uid.origin.container->begin() );
						break;
					}
				}
				else
				{
					// Log skipping of path if verbose.
					//
					if constexpr ( verbose )
						io::log<CON_CYN>( "Path [%llx->%llx] is not taken as it's n-looping.\n", lookup.uid.origin.container->entry_vip, it.container->entry_vip );
				}
			}
		}

		// If resolved result is not valid, assign the default result.
		//
		if ( !result.is_valid() )
			result = default_result + default_result_offset;

		// Log the final result if verbose.
		//
		if constexpr ( verbose )
		{
			io::log_padding--;
			io::log( "= %s\n", result.to_string() );
		}
		return result;
	}
};