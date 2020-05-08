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
#include "trace.hpp"

namespace vtil::optimizer
{
    // Internal typedefs.
    //
    using subquery_function_t = std::function<symbolic::expression( bitcnt_t offset, bitcnt_t size )>;

    // Basic tracer with the query_function_t signature implemented using primitive tracer.
    //
    static symbolic::expression trace_basic( const variable& lookup )
    {
        using namespace logger;

#if VTIL_OPT_TRACE_VERBOSE
        // Log the beginning of the query.
        //
        log<CON_BRG>( "Query(%s)\n", lookup.to_string() );
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
        log<CON_BRG>( "= %s\n", result.to_string() );
#endif
        return result;
    };

    // Propagates all variables in the reference expression onto the new iterator given using
    // the query helper given (except of pointer propagation where basic tracer will be used).
    // - Note: New iterator should be a connected block's end.
    //
    static symbolic::expression propagate( const symbolic::expression& ref,
                                           const ilstream_const_iterator& it,
                                           const query_function_t& query )
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
            variable var = uid.get<variable>();

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
                    error( "Local variable %s is used before value assignment.\n", var.to_string() );

                // If volatile iterator cannot be moved, skip.
                //
                if ( var.reg().flags & register_volatile )
                    continue;
            }
            // If memory, propagate the pointer.
            //
            else if ( var.is_memory() )
            {
                auto& pointer = var.mem().pointer;
#if VTIL_OPT_TRACE_VERBOSE
                // Log original pointer.
                //
                log<CON_PRP>( "Propagating pointer: %s\n", pointer->to_string() );
#endif
                // Fail if propagation fails.
                //
                if ( !( pointer = propagate( *pointer, it, trace_basic ) ) )
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
            symbolic::expression var_traced = query( var );
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

    // If a parital write was hit while tracing value, this routine is used to 
    // determine the calls we should make to complete the result in terms of
    // high and low bits, and the final size.
    //
    static symbolic::expression resolve_partial( bitcnt_t write_offset, bitcnt_t read_offset,
                                                 bitcnt_t write_size,   bitcnt_t read_size,
                                                 const subquery_function_t& subquery )
    {
        using namespace logger;

        // Fetch the result of this operation.
        //
        symbolic::expression base = subquery( write_offset, write_size );

        // Query a low part if we have to.
        //
        if ( write_offset > read_offset )
        {
            bitcnt_t low_bcnt = write_offset - read_offset;
            auto res = subquery( read_offset, low_bcnt );
#if VTIL_OPT_TRACE_VERBOSE
            // Log the low and middle bits.
            //
            log<CON_RED>( "dst[00..%02d] := %s\n", low_bcnt, res.to_string() );
            log<CON_YLW>( "dst[%02d..%02d] := %s\n", write_offset - read_offset, write_offset + write_size - read_offset, base.to_string() );
#endif
            base = res | ( base.resize( read_size ) << low_bcnt );
        }
        // Shift the result if we have to.
        //
        else if ( write_offset < read_offset )
        {
            base = ( base >> ( read_offset - write_offset ) ).resize( read_size );
#if VTIL_OPT_TRACE_VERBOSE
            // Log the low bits after shifting.
            //
            log<CON_YLW>( "dst[00..%02d] := %s\n", write_offset + write_size - read_offset, base.to_string() );
#endif
        }
        else
        {
#if VTIL_OPT_TRACE_VERBOSE
            // Log the low bits.
            //
            log<CON_YLW>( "dst[00..%02d] := %s\n", write_offset + write_size - read_offset, base.to_string() );
#endif
        }

        // Query a high part if we have to.
        //
        if ( ( read_offset + read_size ) > ( write_offset + write_size ) )
        {
            bitcnt_t high_bnct = ( read_offset + read_size ) - ( write_offset + write_size );
            auto res = subquery( write_offset + write_size, high_bnct );
#if VTIL_OPT_TRACE_VERBOSE
            // Log the high bits.
            //
            log<CON_PRP>( "dst[%02d..%02d] := %s\n", write_offset + write_size - read_offset, read_offset + read_size, res.to_string() );
#endif
            base = base | ( res.resize( read_size ) << ( write_offset + write_size - read_offset ) );
        }

#if VTIL_OPT_TRACE_VERBOSE
        // Log the final result.
        //
        log<CON_GRN>( "dst         := %s\n", base.to_string() );
#endif
        // Resize and return.
        //
        return base.resize( read_size );
    }

    // Traces a variable across the basic block's instruction stream it belongs to. 
    // Invokes the passed query helper for any subqueries it generates.
    //
    symbolic::expression trace_primitive( variable lookup, const query_function_t& query )
    {
        using namespace logger;

        // If null iterator or register with "no-trace" flags, return as is.
        //
        if ( !lookup.at.is_valid() ||
            ( lookup.is_register() && ( lookup.reg().flags & ( register_volatile | register_readonly ) ) ) )
            return lookup.to_expression();

        // Declare a helper to convert operands of current instruction into expressions.
        //
        auto cvt_operand = [ & ] ( int i ) -> symbolic::expression
        {
            const operand& op = lookup.at->operands[ i ];

            // If operand is a register:
            //
            if ( op.is_register() )
            {
                // Redirect the query.
                //
                auto result = query( { lookup.at, op.reg() } );

                // If stack pointer, add the current virtual offset.
                //
                if ( op.reg().is_stack_pointer() )
                    result = result + lookup.at->sp_offset;

                // Return the result.
                //
                return result;
            }
            // If it is an immediate, convert into constant expression and return.
            //
            else
            {
                fassert( op.is_immediate() );
                return { op.imm().i64, op.imm().bit_count };
            }
        };

        // If register:
        //
        if ( lookup.is_register() )
        {
            auto& reg = lookup.reg();

            // Fast forward until iterator writes to the lookup, if none found return as is.
            //
            while ( true )
            {
                // If we reached the beginning without any modifications, redirect to query helper.
                //
                if ( lookup.at.is_begin() )
                    return query( lookup );

                // Decrement iterator.
                //
                --lookup.at;

                // If instruction writes into the register:
                //
                if ( int idx = lookup.at->writes_to( reg ) )
                {
                    // If size or offset does not mismatch:
                    //
                    auto& write_at = lookup.at->operands[ idx - 1 ].reg();
                    if ( write_at.bit_offset != reg.bit_offset ||
                         write_at.bit_count != reg.bit_count )
                    {
                        // Define sub-query helper.
                        //
                        variable tmp = { std::next( lookup.at ), reg };
                        auto subquery = [ & ] ( bitcnt_t bit_offset, bitcnt_t bit_count )
                        {
                            tmp.reg().bit_offset = bit_offset;
                            tmp.reg().bit_count = bit_count;
                            return query( tmp );
                        };

                        // Redirect to partial resolver.
                        //
                        return resolve_partial(
                            write_at.bit_offset, reg.bit_offset,
                            write_at.bit_count, reg.bit_count,
                            subquery
                        );
                    }
                    break;
                }
            }

            // If MOV:
            //
            if ( *lookup.at->base == ins::mov )
            {
                // Return source operand.
                //
                return cvt_operand( 1 ).resize( reg.bit_count );
            }
            // If LDD:
            //
            else if ( *lookup.at->base == ins::ldd )
            {
                // Redirect to source pointer.
                //
                auto [base, offset] = lookup.at->get_mem_loc();
                variable::memory_t mem(
                    query( { lookup.at, base } ) + offset,
                    ( reg.bit_count + 7 ) / 8
                );
                symbolic::expression exp = query( variable( lookup.at, mem ) );

                // Return after resizing if valid or return invalid as memory queries can fail.
                //
                return exp.is_valid() ? exp.resize( reg.bit_count ) : exp;
            }
            // If any symbolic operator:
            //
            else if ( lookup.at->base->symbolic_operator != math::operator_id::invalid )
            {
                math::operator_id op_id = lookup.at->base->symbolic_operator;

                // If [X = F(X)]:
                //
                if ( lookup.at->base->operand_count() == 1 )
                {
                    return symbolic::expression{ op_id, cvt_operand( 0 ) };
                }
                // If [X = F(X, Y)]:
                //
                else if ( lookup.at->base->operand_count() == 2 )
                {
                    return symbolic::expression{ cvt_operand( 0 ), op_id, cvt_operand( 1 ) }.resize( reg.bit_count );
                }
                // If [X = F(Y:X, Z)]:
                //
                else if ( lookup.at->base->operand_count() == 3 )
                {
                    // If high bits are zero:
                    //
                    auto op1_high = cvt_operand( 1 );
                    if ( ( op1_high == 0 ).get().value_or( false ) )
                    {
                        auto op1 = cvt_operand( 0 );
                        return symbolic::expression{ op1, op_id, cvt_operand( 2 ) }.resize( reg.bit_count );
                    }
                    // If high bits are set, but the operation bit-count is equal to or less than 64 bits.
                    //
                    else if ( ( lookup.at->operands[ 0 ].size() + lookup.at->operands[ 1 ].size() ) <= 8 )
                    {
                        auto op1_low = cvt_operand( 0 );
                        auto op1 = op1_low | ( op1_high.resize( op1_high.size() + op1_low.size() ) << op1_low.size() );
                        return symbolic::expression{ op1, op_id, cvt_operand( 2 ) }.resize( reg.bit_count );
                    }
                    // If operation is 65 bits or bigger:
                    //
                    else
                    {
                        // TODO: Implement later on.
                        // -- Fall to unknown operation.
                    }
                }
            }

            // If we could not describe the behaviour, increment iterator and return.
            //
            ++lookup.at;
            return lookup.to_expression();
        }
        // If memory:
        //
        else
        {
            fassert( lookup.is_memory() );
            auto& mem = lookup.mem();

#if VTIL_OPT_TRACE_VERBOSE
            // Log the lookup pointer.
            //
            log<CON_PRP>( "&Lookup:      %s\n", mem.pointer->to_string() );
#endif
            // Fast forward until iterator writes to the lookup, if none found return as is.
            //
            while ( true )
            {
                // If we reached the beginning without any modifications, redirect to query helper.
                //
                if ( lookup.at.is_begin() )
                    return query( lookup );

                // Decrement iterator.
                //
                --lookup.at;

                // Skip if instruction does not write into memory:
                //
                if ( !lookup.at->base->writes_memory() )
                    continue;

                // Generate an expression for the pointer.
                //
                auto [write_base, write_offset] = lookup.at->get_mem_loc();
                auto ptr2 = query( { lookup.at, write_base } ) + write_offset;

                // If displacement can be expressed as a constant:
                //
                if ( auto disp = ( ptr2 - mem.pointer ).get<int64_t>() )
                {
                    // Skip if out of boundary.
                    //
                    if ( ( *disp + lookup.at->access_size() ) <= 0 )
                        continue;
                    if ( *disp >= mem.size )
                        continue;

#if VTIL_OPT_TRACE_VERBOSE
                    // Log the destination pointer.
                    //
                    log<CON_CYN>( "&Destination: %s\n", ptr2.to_string() );
#endif
                    // If size or offset does not mismatch:
                    //
                    if ( *disp != 0 || lookup.at->access_size() != mem.size )
                    {
                        // Define sub-query helper.
                        //
                        variable tmp = { std::next( lookup.at ), mem };
                        auto subquery = [ & ] ( bitcnt_t bit_offset, bitcnt_t bit_count )
                        {
                            fassert( !( ( bit_offset | bit_count ) & 7 ) );
                            tmp.mem().pointer = mem.pointer + bit_offset / 8;
                            tmp.mem().size = bit_count / 8;
                            return query( tmp );
                        };

                        // Redirect to partial resolver.
                        //
                        return resolve_partial(
                            *disp * 8, 0,
                            lookup.at->access_size() * 8, mem.size * 8,
                            subquery
                        );
                    }
                    break;
                }
                // Otherwise, fail if neither are restricted pointers.
                //
                else
                {
                    // Check if lookup pointer contains $sp.
                    //
                    bool p1_sp = false;
                    mem.pointer->enumerate( [ & ] ( const symbolic::expression& exp )
                    {
                        if ( exp.is_variable() )
                        {
                            auto& var = exp.uid.get<variable>();
                            p1_sp |= var.is_register() && var.reg().is_stack_pointer();
                        }
                    } );
                    // Check if written pointer contains $sp.
                    //
                    bool p2_sp = false;
                    ptr2.enumerate( [ & ] ( const symbolic::expression& exp )
                    {
                        if ( exp.is_variable() )
                        {
                            auto& var = exp.uid.get<variable>();
                            p2_sp |= var.is_register() && var.reg().is_stack_pointer();
                        }
                    } );

                    // If only one contains $sp and is non-complex pointer, continue iteration.
                    // - Since $sp is a __restrict qualified pointer, we can assume
                    //   that none of the registers will be pointing at it.
                    //
                    if ( ( p1_sp && !p2_sp && mem.pointer->depth <= 1 ) ||
                        ( p2_sp && !p1_sp && ptr2.depth <= 1 ) )
                    {
#if VTIL_OPT_TRACE_VERBOSE
                        // Log the decision.
                        //
                        log<CON_BLU>( "[Variable displacement over restricted pointer, skipped.]\n" );
#endif
                        continue;
                    }
                    else
                    {
#if VTIL_OPT_TRACE_VERBOSE
                        // Log the decision.
                        //
                        log<CON_RED>( "[Variable displacement, unknown memory state.]\n" );
#endif
                    }

                    // Otherwise return as unknown.
                    //
                    ++lookup.at;
                    return lookup.to_expression();
                }
            }

            // If STR:
            //
            if ( *lookup.at->base == ins::str )
            {
                // Return source operand.
                //
                return cvt_operand( 2 ).resize( mem.size * 8 );
            }

            // If we could not describe the behaviour, increment iterator and return.
            //
            ++lookup.at;
            return  lookup.to_expression();
        }
    }

    // Traces a variable recursively across all possible paths.
    //
    symbolic::expression rtrace_primitive( const variable& lookup, const path_history_t& history )
    {
        using namespace logger;

        // Trace through the current block first.
        //
        symbolic::expression result = trace_basic( lookup );

        // If result has any variables:
        //
        if ( result.count_unique_variables() != 0 )
        {
            // Determine the paths we can take to iterate further.
            //
            std::vector it_list = lookup.at.is_valid()
                ? lookup.at.recurse( false )
                : std::vector<ilstream_const_iterator>{};

            // If there are paths take.
            //
            if ( !it_list.empty() )
            {
#if VTIL_OPT_TRACE_VERBOSE
                // Log recursive tracing of the expression.
                //
                log<CON_GRN>( "Base case: %s\n", result.to_string() );
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
                        return rtrace_primitive( var, history_local );
                    } );

#if VTIL_OPT_TRACE_VERBOSE
                    // Log result.
                    //
                    log<CON_BLU>( "= %s\n", exp.to_string() );
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
                        log<CON_RED>( "Cancelling query as it was not deterministic.\n" );
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
                                    exp.uid.get<variable>().is_branch_dependant = true;
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
        log<CON_BRG>( "= %s\n", result.to_string() );
#endif
        return result;
    }

	// Simple wrappers around primitive trace and rtrace to return in packed format.
	//
	symbolic::expression trace( const variable& lookup ) 
    { 
        return variable::pack_all( trace_basic( lookup ) ); 
    }
    symbolic::expression rtrace( const variable& lookup ) 
    { 
        return variable::pack_all( rtrace_primitive( lookup ) ); 
    }
};