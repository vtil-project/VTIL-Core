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
#include "tracer.hpp"
#include <vtil/io>
#include "../vm/lambda.hpp"

namespace vtil
{
	// Internal type definitions.
	//
	using partial_tracer_t = std::function<symbolic::expression( bitcnt_t offset, bitcnt_t size )>;
	using path_history_t = std::map<std::pair<const basic_block*, const basic_block*>, uint32_t>;

	// Forward defs.
	//
	static symbolic::expression rtrace_primitive( const symbolic::variable& lookup, tracer* tracer, const path_history_t& history );

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
			base = ( base >> access.bit_offset ).resize( bit_count );
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

    // Propagates all variables in the reference expression onto the new iterator, if no history pointer given will do trace instead of rtrace.
    // - Note: New iterator should be a connected block's end.
    //
    static symbolic::expression propagate( const symbolic::expression& ref, const il_const_iterator& it, tracer* tracer, path_history_t* history )
    {
        using namespace logger;
        scope_padding _p( 3 );

        // Copy the reference expression.
        //
        symbolic::expression exp = ref;

        // For each unique variable:
        //
        std::set<symbolic::unique_identifier> variables;
        ref.count_unique_variables( &variables );
        for ( auto& uid : variables )
        {
            // Move the variable to reference the previous block.
            //
            symbolic::variable var = uid.get<symbolic::variable>();

            // Skip if variable is position indepdendent or not at the beginning of the block.
            //
            if ( !var.at.is_valid() || !var.at.is_begin() )
                continue;

            // If register:
            //
            if ( var.is_register() )
            {
                // Local temporary must not exist in an expression being propagated
                // from the beginning of the block as that indicates use before assignment.
                // Make sure this is not the case.
                //
                if ( var.reg().flags & register_local )
                    error( "Local variable %s is used before value assignment.\n", var );

                // If volatile iterator cannot be moved, skip.
                //
                if ( var.reg().flags & register_volatile )
                    continue;
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
				if ( !( mem = { propagate( mem.decay(), it, tracer, nullptr ), mem.bit_count } ).decay() )
                    return {};

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
			symbolic::expression var_traced = history 
				? rtrace_primitive( var, tracer, *history )
				: tracer->trace( var );
            if ( !var_traced )
                return {};

            // If we are tracing the value of RSP, add the stack pointer delta between blocks.
            //
            if ( var.is_register() && var.reg().is_stack_pointer() )
                var_traced = var_traced + it.container->sp_offset;

            // Rewrite the expression
            //
            exp.transform( [ & ] ( symbolic::expression& exp )
            {
                if ( exp.is_variable() && exp.uid == uid )
                    exp = var_traced;
            } );
        }

        // Return the result.
        //
        return exp;
    }

	// Internal implementation of ::rtrace with a path history.
	//
	static symbolic::expression rtrace_primitive( const symbolic::variable& lookup, tracer* tracer, const path_history_t& history )
	{
		using namespace logger;

		// Trace through the current block first.
		//
		symbolic::expression result = tracer->trace( lookup );

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
					// Create a local copy for the visited list for this path 
					// and increment the visit counter.
					//
					path_history_t history_local = { history };
					uint32_t& visit_counter = history_local[ { lookup.at.container, it.container } ];

					// If we've taken this path more than twice, skip it.
					//
					if ( ++visit_counter > 2 )
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
					// Propagate each variable onto to the destination block.
					//
					symbolic::expression exp = propagate( default_result, it, tracer, &history_local );

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
						// If it was mismatchign, return default result as branch dependant.
						//
						else
						{
							result = default_result;
							result.transform( [ ] ( symbolic::expression& exp )
							{
								if ( exp.is_variable() )
									exp.uid.get<symbolic::variable>().is_branch_dependant = true;
							}, false );
						}
						break;
					}
				}
			}
		}
#if VTIL_OPT_TRACE_VERBOSE
		// Log result.
		//
		log<CON_BRG>( "= %s\n", result );
#endif
		return result;
	}

	// Traces a variable across the basic block it belongs to and generates a symbolic expression 
	// that describes it's value at the bound point. The provided variable should not contain a 
	// pointer with out-of-block expressions.
	//
	symbolic::expression tracer::trace( symbolic::variable lookup )
	{
		using namespace logger;

		// If invalid/.begin() iterator or register with "no-trace" flags, return as is.
		//
		if ( lookup.at.is_begin() || ( lookup.is_register() && ( lookup.reg().flags & ( register_volatile | register_readonly ) ) ) )
			return lookup.to_expression();

	#ifdef _DEBUG
		// If memory, make sure pointer is expressed as a variable within current block.
		//
		if ( lookup.is_memory() )
		{
			using validator_t = std::function<void( const symbolic::expression& )>;
			static const std::function<validator_t( const basic_block* )> make_validator = [ ] ( const basic_block* container )
			{
				return[ container = std::move( container ) ]( auto& exp )
				{
					if ( exp.is_variable() )
					{
						// Make sure it either has no iterator or belongs to the current container.
						//
						auto& var = exp.uid.get<symbolic::variable>();
						fassert( !var.at.is_valid() || var.at.container == container );

						// If memory variable, validate pointer as well.
						//
						if ( var.is_memory() )
							var.mem().decay().enumerate( make_validator( container ) );
					}
				};
			};
			lookup.mem().decay().enumerate( make_validator( lookup.at.container ) );
		}
	#endif

		// Fast forward until iterator writes to the lookup, if none found return as is.
		//
		symbolic::access_details details = {};
		while ( true )
		{
			// If we reached the beginning, return as is.
			//
			if ( lookup.at.is_begin() )
				return lookup.to_expression();

			// Decrement iterator.
			//
			--lookup.at;

			// If variable is being written to, break.
			//
			if ( details = lookup.written_by( lookup.at, this ) )
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
					return lookup.bind( std::next( lookup.at ) ).to_expression();
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
				ptrace = [ &, &reg = lookup.reg(),
					it = std::next( lookup.at ) ]( bitcnt_t bit_offset, bitcnt_t bit_count )
				{
					symbolic::variable::register_t tmp = {
						reg.flags,
						reg.local_id,
						bit_count,
						reg.bit_offset + bit_offset
					};
					return trace( { it, tmp } );
				};
			}
			else
			{
				ptrace = [ &, &mem = lookup.mem(),
					it = std::next( lookup.at ) ]( bitcnt_t bit_offset, bitcnt_t bit_count )
				{
					fassert( !( ( bit_offset | bit_count ) & 7 ) );
					symbolic::variable::memory_t tmp = {
						mem.decay() + bit_offset / 8,
						bit_count
					};
					return trace( { it, tmp } );
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
			return trace( { lookup.at, desc } );
		};
		lvm.hooks.read_memory = [ & ] ( const symbolic::expression& pointer, size_t byte_count )
		{
			auto exp = trace( symbolic::variable{
				lookup.at, { pointer, bitcnt_t( byte_count * 8 ) }
			} );
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
		if ( lvm.execute( *lookup.at ), result )
			return result;

		// If we could not describe the behaviour, increment iterator and return.
		//
		return lookup.bind( std::next( lookup.at ) ).to_expression();
	}

	// Traces a variable across the entire routine and tries to generates a symbolic expression
	// for it at the specified point of the block.
	//
	symbolic::expression tracer::rtrace( symbolic::variable lookup )
	{
		return rtrace_primitive( lookup, this, {} );
	}
};