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
#include <vtil/utility>

namespace vtil
{
	// Internal type definitions.
	//
	using path_map_t = std::map<std::pair<const basic_block*, const basic_block*>, int>;

	// Forward defs.
	//
	static symbolic::expression::reference rtrace_primitive( const symbolic::variable& lookup, tracer* tracer, path_map_t& path_map, const basic_block* target );

	// Given a partial tracer, this routine will determine the full value of the variable
	// at the given position where a partial write was found.
	//
	static symbolic::expression::reference resolve_partial( const symbolic::variable& origin, 
															const symbolic::access_details& access, 
															function_view<symbolic::expression::reference( const symbolic::variable& )> ptracer )
	{
		using namespace logger;

		auto select = [ & ] ( bitcnt_t bit_offset, bitcnt_t bit_count ) -> symbolic::variable
		{
			if ( origin.is_register() )
				return { origin.at, origin.reg().select( bit_count, origin.reg().bit_offset + bit_offset ) };
			else
				return { origin.at, { origin.mem().base + ( bit_offset / 8 ), bit_count } };
		};
		bitcnt_t bit_count = origin.bit_count();

		// Fetch the result of this operation.
		//
		auto base = ptracer( select( access.bit_offset, access.bit_count ) );

		// Trace a low part if we have to.
		//
		if ( access.bit_offset > 0 )
		{
			bitcnt_t low_bcnt = access.bit_offset;
			auto res = ptracer( select( 0, low_bcnt ) );
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
			auto res = ptracer( select( access.bit_offset + access.bit_count, high_bnct ) );
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
	static void transform_variables( symbolic::expression::reference& inout, function_view<symbolic::expression::reference(const symbolic::variable&)> fn )
	{
		// Take fast path if single variable.
		//
		if ( inout->is_variable() )
		{
			if ( symbolic::expression::reference res = fn( inout->uid.get<symbolic::variable>() ) )
				inout = res;
			return;
		}

		std::unordered_map<symbolic::variable, symbolic::expression::reference> cache;
		cache.reserve( inout->depth );
		
		inout.transform( [ &cache, &fn ] ( symbolic::expression::delegate& exp )
		{
			// Skip if not variable.
			//
			if ( !exp->is_variable() )
				return;

			// Apply transformation.
			//
			auto& var = exp->uid.get<symbolic::variable>();
			if ( auto it = cache.find( var ); it != cache.end() )
			{
				if ( it->second && *it->second )
					exp = it->second;
			}
			else
			{
				auto res = fn( var );
				auto [cit, _] = cache.emplace( var, std::move( res ) );

				if ( cit->second && *cit->second )
					exp = cit->second;
			}
		}, true, false );
	}

    // Propagates all variables in the reference expression onto the new iterator, if no history pointer given will do trace instead of rtrace.
	// Returns an additional boolean parameter that indicates, if the propagation failed, it was due to a total failure or not; total failure
	// meaning the origin expression was a variable and it infinite-looped during propagation by itself.
    // - Note: New iterator should be a connected block's end.
	//
    static bool propagate( symbolic::expression::reference& ref, const il_const_iterator& it, tracer* tracer, path_map_t* path_map, const basic_block* target )
    {
        using namespace logger;

#if VTIL_OPT_TRACE_VERBOSE
        scope_padding _p( 1 );
#endif

		std::optional<bool> result = {};
		transform_variables( ref, [ & ] ( const symbolic::variable& _var ) -> symbolic::expression::reference
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
						"Local variable %s is used before value assignment (Block %x).\n",
						var,
						var.at.block->entry_vip
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
				propagate( mem_ptr, it, tracer->purify(), nullptr, nullptr );
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
			symbolic::expression::reference var_traced;
			if ( path_map )
				var_traced = rtrace_primitive( var, tracer, *path_map, target );
			else
				var_traced = tracer->trace( var );
			if ( !var_traced )
			{
				result = ref->is_variable();
				return {};
			}

            // If we are tracing the value of RSP, add the stack pointer delta between blocks.
            //
            if ( var.is_register() && var.reg().is_stack_pointer() && it.block->sp_offset )
                var_traced = var_traced + it.block->sp_offset;
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
	static symbolic::expression::reference rtrace_primitive( const symbolic::variable& lookup, tracer* tracer, path_map_t& path_map, const basic_block* target )
	{
		using namespace logger;

		// Save whether this is the call whose result will reach the user.
		//
		bool initial_call = path_map.empty();

		// Trace through the current block first.
		//
		auto result = tracer->trace( lookup );

		// If result has any variables:
		//
		if ( result->value.is_unknown() )
		{
			// Save current result as default result and clear it.
			//
			symbolic::expression::reference default_result = {};
			std::swap( result, default_result );

			// If there may be paths to enumerate:
			//
			size_t count = 0;
			if ( lookup.at.is_valid() )
			{
				// Determine whether we're in a loop or not.
				//
				bool potential_loop = lookup.at.block->owner->is_looping( lookup.at.block );

				// If block does not touch our variable, skip the logic.
				//
				/*if ( default_result->is_variable() &&
					 default_result->uid.get<symbolic::variable>().at.is_begin() &&
					 default_result->uid.get<symbolic::variable>().descriptor == lookup.descriptor )
					potential_loop = false;

				// Make an exception for self looping blocks.
				//
				for ( auto& it : it_list )
					potential_loop |= it.block == lookup.at.block;*/

				// Enumerate each path:
				//
				lookup.at.enum_paths( false, [ & ] ( const il_const_iterator& it )
				{
					// Skip if it does not reach target.
					//
#if _DEBUG
					if ( !target->owner->has_path( it.block, target ) )
					{
						warning( "Iterator %s has no path to %s but is still being considered in backpropagation.",
							   it, target->begin() );
					}
#endif

					// Increment path count.
					//
					if ( ++count == 0 )
					{
#if VTIL_OPT_TRACE_VERBOSE
						// Log recursive tracing of the expression.
						//
						log<CON_GRN>( "Base case: %s\n", result );
#endif
					}

					// If we've taken this path more than twice, skip it.
					//
					if ( potential_loop )
					{
						int& counter = path_map[ { lookup.at.block, it.block } ];
						if ( counter >= 2 )
						{
#if VTIL_OPT_TRACE_VERBOSE
							// Log skipping of path.
							//
							log<CON_CYN>( "Path [%llx->%llx] is not taken as it's n-looping.\n", lookup.at.block->entry_vip, it.block->entry_vip );
#endif
							return enumerator::ocontinue;
						}
						++counter;
					}

#if VTIL_OPT_TRACE_VERBOSE
					// Log tracing of path.
					//
					log<CON_YLW>( "Taking path [%llx->%llx]\n", lookup.at.block->entry_vip, it.block->entry_vip );
#endif
					// Propagate each variable onto to the destination block, if total fail, skip path.
					//
					symbolic::expression::reference exp = default_result;
					bool total_fail = propagate( exp, it, tracer, &path_map, target );
					if ( potential_loop )
						path_map[ { lookup.at.block, it.block } ]--;
					if ( total_fail )
						return enumerator::ocontinue;

#if VTIL_OPT_TRACE_VERBOSE
					// Log result.
					//
					log<CON_BLU>( "= %s\n", exp );
#endif
					// If no result is set yet, assign the current expression.
					//
					if ( !result )
						result = exp;

					// If expression is invalid or not equal to previous result, fail.
					//
					if ( !exp || !exp->equals( *result ) )
					{
#if VTIL_OPT_TRACE_VERBOSE
						// Log decision.
						//
						log<CON_RED>( "Halting tracer as it was not deterministic.\n" );
#endif
						// If result was null, return lookup.
						//
						if ( !exp )
						{
							result = lookup.to_expression();
						}
						// If it was mismatching, return default result as branch dependant.
						//
						else
						{
							result = std::move( default_result );
							result.transform( [ ] ( symbolic::expression::delegate& exp )
							{
								if ( exp->is_variable() )
								{
									symbolic::variable&& var = std::move( ( +exp )->uid.get<symbolic::variable>() );
									var.is_branch_dependant = true;
									*+exp = { var, exp->size() };
								}
							}, true, false );
						}
						return enumerator::obreak;
					}
					return enumerator::ocontinue;
				} );
			}

			// If result is null, use default result instead if the call will reach the user,
			// or if there were simply no paths to take.
			//
			if ( !result && ( initial_call || count == 0 ) )
				result = std::move( default_result );
		}
#if VTIL_OPT_TRACE_VERBOSE
		// Log result.
		//
		log<CON_BRG>( "= %s\n", result );
#endif
		return result.simplify();
	}

	// Traces a variable across the basic block it belongs to and generates a symbolic expression 
	// that describes it's value at the bound point. The provided variable should not contain a 
	// pointer with out-of-block expressions.
	//
	symbolic::expression::reference tracer::trace( const symbolic::variable& lookup )
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
			// Redirect to partial resolver.
			//
			symbolic::variable origin = { std::next( it ), lookup.descriptor };
			return resolve_partial( origin, details, [ & ] ( const symbolic::variable& var ) { return tracer::trace( std::move( var ) ); } );
		}

		// Create a lambda virtual machine and allocate a temporary result.
		//
		lambda_vm lvm;
		symbolic::expression::reference result = {};

		lvm.hooks.read_register = [ & ] ( const register_desc& desc )
		{
			return trace( { it, desc } );
		};
		lvm.hooks.read_memory = [ & ] ( const symbolic::expression::reference& pointer, size_t byte_count )
		{
			auto exp = trace( symbolic::variable{ it, { pointer, math::narrow_cast<bitcnt_t>( byte_count * 8 ) } } );
			return exp ? exp.resize( result_bcnt ) : exp;
		};
		lvm.hooks.write_register = [ & ] ( const register_desc& desc, symbolic::expression::reference value )
		{
			if ( desc == lookup.reg() )
				result = std::move( value );
		};

		lvm.hooks.write_memory = [ & ] ( const symbolic::expression::reference& pointer, deferred_value<symbolic::expression::reference> value, bitcnt_t size )
		{
			if ( pointer->equals( *lookup.mem().decay() ) )
				result = std::move( value.get() );
			return true;
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
	symbolic::expression::reference tracer::rtrace( const symbolic::variable& lookup )
	{
		bool recursive_flag_prev = std::exchange( recursive_flag, true );
		path_map_t path_map = {};
		auto exp = rtrace_primitive( lookup, this, path_map, lookup.at.block );
		recursive_flag = recursive_flag_prev;
		return exp;
	}
	
	// Wrappers around trace and rtrace that can trace an entire expression.
	//
	symbolic::expression::reference tracer::trace_exp( const symbolic::expression::reference& exp )
	{
		symbolic::expression::reference out = exp;
		transform_variables( out, [ & ] ( const symbolic::variable& var ) { return trace( var ); } );
		return out.simplify();
	}
	symbolic::expression::reference tracer::rtrace_exp( const symbolic::expression::reference& exp )
	{
		symbolic::expression::reference out = exp;
		transform_variables( out, [ & ] ( const symbolic::variable& var ) { return rtrace( var ); } );
		return out.simplify();
	}
};