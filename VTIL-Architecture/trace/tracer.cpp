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
// 3. Neither the name of VTIL Project nor the names of its contributors
//    may be used to endorse or promote products derived from this software 
//    without specific prior written permission.   
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
#include "tracer.hpp"
#include <vtil/io>
#include "../vm/lambda.hpp"

namespace vtil
{
	// Internal type definitions.
	//
	struct path_entry
	{
		const path_entry* prev;
		const basic_block* src;
		const basic_block* dst;

		size_t count( const basic_block* srcx, const basic_block* dstx ) const
		{
			size_t n = 0;
			for ( auto it = this; it; it = it->prev )
				n += it->src == srcx && it->dst == dstx;
			return n;
		}
	};

	using partial_tracer_t = std::function<symbolic::expression( bitcnt_t offset, bitcnt_t size )>;

	// Forward defs.
	//
	static void rtrace_primitive( symbolic::expression& out, const symbolic::variable& lookup, tracer* tracer, path_entry* prev_link, int64_t );

	// Given a partial tracer, this routine will determine the full value of the variable
	// at the given position where a partial write was found.
	//
	static symbolic::expression resolve_partial( const symbolic::access_details& access, bitcnt_t bit_count, const partial_tracer_t& ptracer )
	{
		using namespace logger;

		// Fetch the result of this operation.
		//
		symbolic::expression base = ptracer( access.bit_offset, access.bit_count );

		// Trace a low part if we have to.
		//
		if ( access.bit_offset > 0 )
		{
			bitcnt_t low_bcnt = access.bit_offset;
			auto res = ptracer( 0, low_bcnt );
#if VTIL_OPT_TRACE_VERBOSE
			// Log the low and middle bits.
			//
			log<CON_RED>( "dst[00..%02d] := %s\n", low_bcnt, res );
			log<CON_YLW>( "dst[%02d..%02d] := %s\n", access.bit_offset, access.bit_offset + access.bit_count, base );
#endif
			base = res | ( base.resize( bit_count ) << low_bcnt );
		}
		// Shift the result if we have to.
		//
		else if ( access.bit_offset < 0 )
		{
			base = ( base >> -access.bit_offset ).resize( bit_count );
#if VTIL_OPT_TRACE_VERBOSE
			// Log the low bits after shifting.
			//
			log<CON_YLW>( "dst[00..%02d] := %s\n", access.bit_offset + access.bit_count, base );
#endif
		}
		else
		{
#if VTIL_OPT_TRACE_VERBOSE
			// Log the low bits.
			//
			log<CON_YLW>( "dst[00..%02d] := %s\n", access.bit_offset + access.bit_count, base );
#endif
		}

		// Trace a high part if we have to.
		//
		if ( bit_count > ( access.bit_offset + access.bit_count ) )
		{
			bitcnt_t high_bnct = bit_count - ( access.bit_offset + access.bit_count );
			auto res = ptracer( access.bit_offset + access.bit_count, high_bnct );
#if VTIL_OPT_TRACE_VERBOSE
			// Log the high bits.
			//
			log<CON_PRP>( "dst[%02d..%02d] := %s\n", access.bit_offset + access.bit_count, bit_count, res );
#endif
			base = base | ( res.resize( bit_count ) << ( access.bit_offset + access.bit_count ) );
		}

#if VTIL_OPT_TRACE_VERBOSE
		// Log the final result.
		//
		log<CON_GRN>( "dst         := %s\n", base );
#endif
		// Resize and return.
		//
		return base.resize( bit_count );
	}

	// Applies transformation per each unique variable in the expression.
	//
	static void transform_variables( symbolic::expression& inout, const std::function<symbolic::expression(const symbolic::variable&)>& fn )
	{
		// Take fast path if single variable.
		//
		if ( inout.is_variable() )
		{
			inout = fn( inout.uid.get<symbolic::variable>() );
			return;
		}

		std::unordered_map<symbolic::variable, symbolic::expression, hasher<>> cache;
		cache.reserve( inout.depth );
		inout.transform( [ &cache, &fn ] ( symbolic::expression& exp )
		{
			// Skip if not variable.
			//
			if ( !exp.is_variable() )
				return;

			// Apply transformation.
			//
			symbolic::variable& var = exp.uid.get<symbolic::variable>();
			if ( auto it = cache.find( var ); it != cache.end() )
			{
				if ( it->second ) 
					exp = it->second;
			}
			else
			{
				auto res = fn( var );
				auto [cit, _] = cache.emplace( var, std::move( res ) );
				
				if( cit->second )
					exp = cit->second;
			}
		}, true, false );
	}


    // Propagates all variables in the reference expression onto the new iterator, if no history pointer given will do trace instead of rtrace.
	// Returns an additional boolean parameter that indicates, if the propagation failed, it was due to a total failure or not; total failure
	// meaning the origin expression was a variable and it infinite-looped during propagation by itself.
    // - Note: New iterator should be a connected block's end.
	//
    static bool propagate( symbolic::expression& ref, const il_const_iterator& it, tracer* tracer, path_entry* prev_link, int64_t limit )
    {
        using namespace logger;

#if VTIL_OPT_TRACE_VERBOSE
        scope_padding _p( 1 );
#endif

		std::optional<bool> result = {};
		transform_variables( ref, [ & ] ( const symbolic::variable& _var ) -> symbolic::expression
		{
			// If result is already decided, return as is.
			//
			if ( result.has_value() ) 
				return {};

			// Move the variable to reference the previous block.
            //
            symbolic::variable var = _var;

            // Skip if variable is position indepdendent or not at the beginning of the block.
            //
            if ( !var.at.is_valid() || !var.at.is_begin() )
				return {};

            // If register:
            //
            if ( var.is_register() )
            {
                // Local temporary must not exist in an expression being propagated
                // from the beginning of the block as that indicates use before assignment.
                // Make sure this is not the case.
                //
				if ( var.reg().flags & register_local )
				{
					warning( 
						"Local variable %s is used before value assignment (Block %x:%x).\n", 
						var, 
						var.at.container->owner->entry_point->entry_vip, 
						var.at.container->entry_vip 
					);
				}

                // If volatile iterator cannot be moved, skip.
                //
                if ( var.reg().flags & register_volatile )
					return {};
            }
            // If memory, propagate the pointer.
            //
			else if ( var.is_memory() )
			{
				auto& mem = var.mem();

#if VTIL_OPT_TRACE_VERBOSE
				// Log original pointer.
				//
				log<CON_PRP>( "Propagating pointer: %s\n", mem.decay() );
#endif
				// Fail if propagation fails.
				//
				symbolic::expression::reference mem_ptr = std::move( mem.base.base );
				propagate( *+mem_ptr, it, tracer, nullptr, limit );
				if ( !mem_ptr )
				{
					result = false;
					return {};
				}
				mem = { mem_ptr, mem.bit_count };

#if VTIL_OPT_TRACE_VERBOSE
                // Log new pointer.
                //
                log<CON_PRP>( "Pointer' => %s\n", mem.decay() );
#endif
            }

            // Move the assigned iterator.
            //
            var.bind( it );

            // Trace the variable in the destination block, fail if it fails.
            //
			symbolic::expression var_traced;
			if ( prev_link )
				rtrace_primitive( var_traced, var, tracer, prev_link, limit );
			else
				var_traced = tracer->trace( var );
			if ( !var_traced )
			{
				result = ref.is_variable();
				return {};
			}

            // If we are tracing the value of RSP, add the stack pointer delta between blocks.
            //
            if ( var.is_register() && var.reg().is_stack_pointer() && it.container->sp_offset )
                var_traced = var_traced + it.container->sp_offset;
			return var_traced;
		} );

        // Return the result.
        //
		if ( !result.has_value() )
		{
			ref.simplify();
			return false;
		}
		ref = {};
		return *result;
    }

	// Internal implementation of ::rtrace with a path history.
	//
	static void rtrace_primitive( symbolic::expression& out, const symbolic::variable& lookup, tracer* tracer, path_entry* prev_link, int64_t limit )
	{
		using namespace logger;

		// Trace through the current block first.
		//
		symbolic::expression result = tracer->trace( lookup );

		// If limit was reached, return as is.
		//
		if ( --limit == 0 )
		{
			out = result;
			return;
		}

		// If result has any variables:
		//
		if ( result.count_unique_variables() != 0 )
		{
			// Determine the paths we can take to iterate further.
			//
			std::vector it_list = lookup.at.is_valid()
				? lookup.at.recurse( false )
				: std::vector<il_const_iterator>{};

			// If there are paths take.
			//
			if ( !it_list.empty() )
			{
#if VTIL_OPT_TRACE_VERBOSE
				// Log recursive tracing of the expression.
				//
				log<CON_GRN>( "Base case: %s\n", result );
#endif
				// Save current result as default result and clear it.
				//
				symbolic::expression default_result = {};
				std::swap( result, default_result );

				// For each path:
				//
				for ( auto& it : it_list )
				{
					// If we've taken this path more than twice, skip it.
					//
					if ( prev_link->count( lookup.at.container, it.container ) >= 2 )
					{
#if VTIL_OPT_TRACE_VERBOSE
						// Log skipping of path.
						//
						log<CON_CYN>( "Path [%llx->%llx] is not taken as it's n-looping.\n", lookup.at.container->entry_vip, it.container->entry_vip );
#endif
						continue;
					}

#if VTIL_OPT_TRACE_VERBOSE
					// Log tracing of path.
					//
					log<CON_YLW>( "Taking path [%llx->%llx]\n", lookup.at.container->entry_vip, it.container->entry_vip );
#endif
					// Propagate each variable onto to the destination block, if total fail, skip path.
					//
					path_entry entry = {
						.prev = prev_link,
						.src = lookup.at.container,
						.dst = it.container
					};
					symbolic::expression exp = default_result;
					if ( propagate( exp, it, tracer, &entry, limit ) )
						continue;

#if VTIL_OPT_TRACE_VERBOSE
					// Log result.
					//
					log<CON_BLU>( "= %s\n", exp );
#endif
					// If no result is set yet, assign the current expression.
					//
					if ( !result.is_valid() )
						result = exp;

					// If expression is invalid or not equal to previous result, fail.
					//
					if ( !exp.is_valid() || !exp.equals( result ) )
					{
#if VTIL_OPT_TRACE_VERBOSE
						// Log decision.
						//
						log<CON_RED>( "Halting tracer as it was not deterministic.\n" );
#endif
						// If result was null, return lookup.
						//
						if ( !exp.is_valid() )
						{
							result = lookup.to_expression();
						}
						// If it was mismatching, return default result as branch dependant.
						//
						else
						{
							result = default_result;
							result.transform( [ ] ( symbolic::expression& exp )
							{
								if ( exp.is_variable() )
									exp.uid.get<symbolic::variable>().is_branch_dependant = true;
							}, true, false );
						}
						break;
					}
				}

				// If result is null, use default result if the call was not from propagate(),
				// determined by history having entries set.
				//
				if ( !result && prev_link->prev == nullptr ) 
					result = std::move( default_result );
			}
		}
#if VTIL_OPT_TRACE_VERBOSE
		// Log result.
		//
		log<CON_BRG>( "= %s\n", result );
#endif
		out = result.simplify();
	}

	// Traces a variable across the basic block it belongs to and generates a symbolic expression 
	// that describes it's value at the bound point. The provided variable should not contain a 
	// pointer with out-of-block expressions.
	//
	symbolic::expression tracer::trace( const symbolic::variable& lookup )
	{
		using namespace logger;

		// If invalid/.begin() iterator or register with "no-trace" flags, return as is.
		//
		if ( lookup.at.is_begin() || ( lookup.is_register() && ( lookup.reg().flags & ( register_volatile | register_readonly ) ) ) )
			return lookup.to_expression();

		// Fast forward until iterator writes to the lookup, if none found return as is.
		//
		symbolic::access_details details = {};
		il_const_iterator it = lookup.at;
		while ( true )
		{
			// If we reached the beginning, return as is.
			//
			if ( it.is_begin() )
				return symbolic::variable{ it, lookup.descriptor }.to_expression();

			// Decrement iterator.
			//
			--it;

			// If variable is being written to, break.
			//
			if ( details = lookup.written_by( it, this, recursive_flag ) )
			{
				// If unknown access, return unknown.
				//
				if ( details.is_unknown() )
				{
#if VTIL_OPT_TRACE_VERBOSE
					// Log the state.
					//
					log<CON_RED>( "[Unknown symbolic state.]\n" );
#endif
					return lookup.to_expression();
				}
				break;
			}
		}

		// If fails due to offset/size mismatch, invoke partial tracer.
		//
		bitcnt_t result_bcnt = lookup.bit_count();
		if ( details.bit_offset != 0 || details.bit_count != result_bcnt )
		{
			// Define partial tracer.
			//
			partial_tracer_t ptrace;
			if ( lookup.is_register() )
			{
				ptrace = [ &, &reg = lookup.reg(), it = std::next( it ) ]( bitcnt_t bit_offset, bitcnt_t bit_count )
				{
					symbolic::variable::register_t tmp = {
						reg.flags,
						reg.local_id,
						bit_count,
						reg.bit_offset + bit_offset,
						reg.architecture
					};
					return tracer::trace( { it, tmp } );
				};
			}
			else
			{
				ptrace = [ &, &mem = lookup.mem(), it = std::next( it ) ]( bitcnt_t bit_offset, bitcnt_t bit_count )
				{
					fassert( !( ( bit_offset | bit_count ) & 7 ) );
					symbolic::variable::memory_t tmp = {
						mem.decay() + bit_offset / 8,
						bit_count
					};
					return tracer::trace( { it, tmp } );
				};
			}

			// Redirect to partial resolver.
			//
			return resolve_partial( details, result_bcnt, ptrace );
		}

		// Create a lambda virtual machine and allocate a temporary result.
		//
		lambda_vm lvm;
		symbolic::expression result = {};

		lvm.hooks.read_register = [ & ] ( const register_desc& desc )
		{
			return trace( { it, desc } );
		};
		lvm.hooks.read_memory = [ & ] ( const symbolic::expression& pointer, size_t byte_count )
		{
			auto exp = trace( symbolic::variable{ it, { pointer, math::narrow_cast<bitcnt_t>( byte_count * 8 ) } } );
			return exp.is_valid() ? exp.resize( result_bcnt ) : exp;
		};
		lvm.hooks.write_register = [ & ] ( const register_desc& desc, symbolic::expression value )
		{
			if ( desc == lookup.reg() )
				result = std::move( value );
		};

		lvm.hooks.write_memory = [ & ] ( const symbolic::expression& pointer, symbolic::expression value )
		{
			if ( pointer.equals( lookup.mem().decay() ) )
				result = std::move( value );
		};

		// Step one instruction, if result was successfuly captured, return.
		//
		if ( lvm.execute( *it ), result )
			return result;

		// If we could not describe the behaviour, increment iterator and return.
		//
		return symbolic::variable{ std::next( it ), lookup.descriptor }.to_expression();
	}

	// Traces a variable across the entire routine and tries to generates a symbolic expression
	// for it at the specified point of the block, limit determines the maximum number of blocks 
	// to trace backwards, any negative number implies infinite since it won't reach 0.
	//
	symbolic::expression tracer::rtrace( const symbolic::variable& lookup, int64_t limit )
	{
		bool recursive_flag_prev = recursive_flag;
		recursive_flag = true;
		path_entry list_head = { nullptr, nullptr, nullptr };
		symbolic::expression exp;
		rtrace_primitive( exp, lookup, this, &list_head, limit + 1 );
		recursive_flag = recursive_flag_prev;
		return exp;
	}
	
	// Wrappers around trace and rtrace that can trace an entire expression.
	//
	symbolic::expression tracer::trace_exp( const symbolic::expression& exp )
	{
		symbolic::expression out = exp;
		transform_variables( out, [ & ] ( const symbolic::variable& var ) { return trace( var ); } );
		return out.simplify();
	}
	symbolic::expression tracer::rtrace_exp( const symbolic::expression& exp, int64_t limit )
	{
		symbolic::expression out = exp;
		transform_variables( out, [ & ] ( const symbolic::variable& var ) { return rtrace( var, limit ); } );
		return out.simplify();
	}
};