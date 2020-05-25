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
#include <vtil/vm>
#include "trace.hpp"
#include "variable_aux.hpp"

namespace vtil::optimizer
{
    // Basic tracer with the trace_function_t signature implemented using primitive tracer.
    //
    static symbolic::expression trace_basic( const symbolic::variable& lookup )
    {
        using namespace logger;

#if VTIL_OPT_TRACE_VERBOSE
        // Log the beginning of the trace.
        //
        log<CON_BRG>( "Trace(%s)\n", lookup );
        scope_padding _p( 1 );
#endif

        // If base case reached, convert to an expression and return as is,
        // otherwise invoke primitive tracer.
        //
        symbolic::expression result = lookup.at.is_begin()
            ? lookup.to_expression()
            : trace_primitive( lookup, trace_basic );

#if VTIL_OPT_TRACE_VERBOSE
        // Log result.
        //
        log<CON_BRG>( "= %s\n", result );
#endif
        return result;
    };

    // Propagates all variables in the reference expression onto the new iterator given using
    // the query helper given (except of pointer propagation where basic tracer will be used).
    // - Note: New iterator should be a connected block's end.
    //
    static symbolic::expression propagate( const symbolic::expression& ref,
                                           const il_const_iterator& it,
                                           const trace_function_t& tracer )
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
                auto& pointer = var.mem().decay();
#if VTIL_OPT_TRACE_VERBOSE
                // Log original pointer.
                //
                log<CON_PRP>( "Propagating pointer: %s\n", pointer->to_string() );
#endif
                // Fail if propagation fails.
                //
                if ( !( pointer = propagate( pointer, it, trace_basic ) ) )
                    return {};

#if VTIL_OPT_TRACE_VERBOSE
                // Log new pointer.
                //
                log<CON_PRP>( "Pointer' => %s\n", pointer->to_string() );
#endif
            }

            // Move the assigned iterator.
            //
            var.at = it;

            // Trace the variable in the destination block, fail if it fails.
            //
            symbolic::expression var_traced = tracer( var );
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

    // Traces a variable across the basic block it belongs to and generates a symbolic expression 
    // that describes it's value at the bound point. Will invoke the passed tracer for any additional 
    // tracing it requires.
    //
    symbolic::expression trace_primitive( symbolic::variable lookup, const trace_function_t& tracer )
    {
        using namespace logger;

        // If null iterator or register with "no-trace" flags, return as is.
        //
        if ( !lookup.at.is_valid() ||
            ( lookup.is_register() && ( lookup.reg().flags & ( register_volatile | register_readonly ) ) ) )
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
        access_details details = {};
        while ( true )
        {
            // If we reached the beginning without any modifications, redirect to the helper passed.
            //
            if ( lookup.at.is_begin() )
                return tracer( lookup );

            // Decrement iterator.
            //
            --lookup.at;

            // If variable is being written to, break.
            //
            if ( details = test_access( lookup.at, lookup.descriptor, access_type::write, tracer ) )
                break;
        }

        // If fails due to offset/size mismatch, invoke partial tracer.
        //
        bitcnt_t result_bcnt = lookup.bit_count();
        if ( !details.is_unknown() &&
            ( details.bit_offset != 0 || details.bit_count != result_bcnt ) )
        {
            // Define partial tracer.
            //
            partial_tracer_t ptrace;
            if ( lookup.is_register() )
            {
                ptrace = [ &, &reg = lookup.reg(), 
                           it = std::next( lookup.at ) ] ( bitcnt_t bit_offset, bitcnt_t bit_count )
                {
                    symbolic::variable::register_t tmp = {
                        reg.flags,
                        reg.local_id,
                        bit_count,
                        reg.bit_offset + bit_offset
                    };
                    return tracer( { it, tmp } );
                };
            }
            else
            {
                ptrace = [ &, &mem = lookup.mem(), 
                           it = std::next( lookup.at ) ] ( bitcnt_t bit_offset, bitcnt_t bit_count )
                {
                    fassert( !( ( bit_offset | bit_count ) & 7 ) );
                    symbolic::variable::memory_t tmp = {
                        mem.decay() + bit_offset / 8,
                        bit_count
                    };
                    return tracer( { it, tmp } );
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
            return tracer( { lookup.at, desc } );
        };
        lvm.hooks.read_memory = [ & ] ( const symbolic::expression& pointer, size_t byte_count )
        {
            auto exp = tracer( symbolic::variable{
                lookup.at, { pointer, bitcnt_t( byte_count * 8 )  }
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

        // If access details are known:
        //
        if ( !details.is_unknown() )
        {
            // Step one instruction, if result was successfuly captured, return.
            //
            if ( lvm.execute( *lookup.at ), result )
                return result;
        }
        // If they are unknown, fallthrough to fail.
        //
        else
        {
#if VTIL_OPT_TRACE_VERBOSE
            // Log the state.
            //
            log<CON_RED>( "[Unknown symbolic state.]\n" );
#endif
        }

        // If we could not describe the behaviour, increment iterator and return.
        //
        ++lookup.at;
        return lookup.to_expression();
    }

    // Traces a variable across the entire routine and generates a symbolic expression that describes 
    // it's value at the bound point. Will invoke the passed tracer for any additional tracing it requires. 
    // Takes an optional path history used internally to recurse in a controlled fashion.
    //
    symbolic::expression rtrace_primitive( const symbolic::variable& lookup, const trace_function_t& tracer, const path_history_t& history )
    {
        using namespace logger;

        // Trace through the current block first.
        //
        symbolic::expression result = tracer( lookup );

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
                    path_history_t history_local = history;
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
                    symbolic::expression exp = propagate( default_result, it, [ & ] ( auto& var ) 
                    { 
                        return rtrace_primitive( var, tracer, history_local );
                    } );

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

	// Simple wrappers around primitive trace and rtrace to return in packed format.
	//
	symbolic::expression trace( const symbolic::variable& lookup, bool pack )
    { 
        symbolic::expression&& result = trace_basic( lookup );
        return pack ? symbolic::variable::pack_all( result ) : result;
    }
    symbolic::expression rtrace( const symbolic::variable& lookup, bool pack )
    {
        symbolic::expression&& result = rtrace_primitive( lookup, trace_basic );
        return pack ? symbolic::variable::pack_all( result ) : result;
    }
};