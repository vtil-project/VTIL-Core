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
#include "transformer.hpp"
#include <vtil/utility>
#include <cstring>
#include "../simplifier/simplifier.hpp"

namespace vtil::symbolic
{
	using namespace directive;

	// Translates the given directive into an expression (of size given) using the symbol table.
	//
	expression::reference translate( const symbol_table_t& sym, const instance* dir, bitcnt_t bit_cnt )
	{
		using namespace logger;
#if VTIL_SYMEX_SIMPLIFY_VERBOSE
		scope_padding _p( 1 );
		log<CON_BLU>( "[%s].\n", *dir );
#endif

		// If expression operator:
		//
		if ( dir->op < math::operator_id::max )
		{
			// If directive is a variable or a constant, translate to expression equivalent.
			//
			if ( dir->op == math::operator_id::invalid )
			{
				if ( !dir->id ) return expression{ dir->get().value(), bit_cnt ? bit_cnt : 64 };
				else            return sym.translate( dir );
			}
			// If it is an expression:
			//
			else
			{
				// Handle casts as a redirect to resize.
				//
				if ( dir->op == math::operator_id::ucast ||
					 dir->op == math::operator_id::cast )
				{
					auto lhs = translate( sym, dir->lhs, 0 );
					if ( !lhs )	return {};
					auto rhs = translate( sym, dir->rhs, bit_cnt );
					if ( !rhs ) return {};

					if ( auto sz = rhs->get<bitcnt_t>() )
					{
						lhs.resize( sz.value(), dir->op == math::operator_id::cast );
						return lhs;
					}
					unreachable();
				}
				// If operation is binary:
				//
				else if ( dir->lhs )
				{
					expression::reference lhs, rhs;

					std::array tx = {
						std::pair( &lhs, dir->lhs.ptr ),
						std::pair( &rhs, dir->rhs.ptr )
					};
					
					if ( tx[ 1 ].second->priority > tx[ 0 ].second->priority )
						std::swap( tx[ 0 ], tx[ 1 ] );

					for( auto& [out, dir] : tx )
						if ( !( *out = translate( sym, dir, bit_cnt ) ) )
							return {};

					return expression::make( std::move( lhs ), dir->op, std::move( rhs ) );
				}
				// If operation is unary:
				//
				else
				{
					auto rhs = translate( sym, dir->rhs, bit_cnt );
					if ( !rhs ) return {};
					return expression::make( dir->op, std::move( rhs ) );
				}
			}
			unreachable();
		}

		// If directive operator:
		//
		switch ( directive_op_desc{ dir->op }.value )
		{
			case directive_op_desc::simplify:
			{
				// If expression translates successfully:
				//
				if ( auto e1 = translate( sym, dir->rhs, bit_cnt ) )
				{
					// Return only if it was successful.
					//
					if ( !e1->simplify_hint && simplify_expression( e1, false, false ) )
						return e1;
				}
#if VTIL_SYMEX_SIMPLIFY_VERBOSE
				log<CON_RED>( "Rejected, does not simplify.\n", *dir->rhs );
#endif
				break;
			}
			case directive_op_desc::try_simplify:
			{
				// Translate right hand side.
				//
				if ( auto e1 = translate( sym, dir->rhs, bit_cnt ) )
				{
					// Simplify the expression.
					//
					simplify_expression( e1, false, false );
					return e1;
				}
				break;
			}
			case directive_op_desc::or_also:
			{
#if VTIL_SYMEX_SIMPLIFY_VERBOSE
				log<CON_BLU>( "Or directive hit %s.\n" );
				log<CON_BLU>( "Trying [%s]...\n", *dir->lhs );
#endif

				// Unpack first expression, if translated successfully, return it as is.
				//
				if ( auto e1 = translate( sym, dir->lhs, bit_cnt ) )
					return e1;

#if VTIL_SYMEX_SIMPLIFY_VERBOSE
				log<CON_BLU>( "Trying [%s]...\n", *dir->rhs );
#endif

				// Unpack second expression, if translated successfully, return it as is.
				//
				if ( auto e2 = translate( sym, dir->rhs, bit_cnt ) )
					return e2;

#if VTIL_SYMEX_SIMPLIFY_VERBOSE
				log<CON_RED>( "Both alternatives failed\n" );
#endif
				break;
			}
			case directive_op_desc::iff:
			{
				static constexpr auto expected = make_expanded_series<VTIL_SYMEX_XVAL_KEYS>( [ ] ( auto ) { return 1ull; } );

				// Translate left hand side, if failed to do so or is not equal to [true], fail.
				//
				auto condition_status = translate( sym, dir->lhs, 0 );
				if ( !condition_status ||
					 memcmp( condition_status->xvalues().data(), expected.data(), expected.size() * sizeof( expected[ 0 ] ) ) ||
					 !condition_status.simplify()->get().value_or( false ) )
				{
#if VTIL_SYMEX_SIMPLIFY_VERBOSE
					log<CON_RED>( "Rejected %s, condition (%s) not met.\n", *dir->rhs, *dir->lhs );
#endif
					return {};
				}

				// Continue the translation from the right hand side.
				//
				condition_status.reset();
				return translate( sym, dir->rhs, bit_cnt );
			}
			case directive_op_desc::mask_unknown:
			{
				// Translate right hand side.
				//
				if ( auto exp = translate( sym, dir->rhs, bit_cnt ) )
				{
					// Return the unknown mask.
					//
					
					return ( *+exp = expression{ exp->unknown_mask(), exp->size() }, exp );
				}
				break;
			}
			case directive_op_desc::mask_one:
			{
				// Translate right hand side.
				//
				if ( auto exp = translate( sym, dir->rhs, bit_cnt ) )
				{
					// Return the unknown mask.
					//
					return ( *+exp = expression{ exp->known_one(), exp->size() }, exp );
				}
				break;
			}
			case directive_op_desc::mask_zero:
			{
				// Translate right hand side.
				//
				if ( auto exp = translate( sym, dir->rhs, bit_cnt ) )
				{
					// Return the unknown mask.
					//
					return ( *+exp = expression{ exp->known_zero(), exp->size() }, exp );
				}
				break;
			}
			case directive_op_desc::unreachable:
			{
				// Print an error.
				//
				error( "Directive-time assertation failure!\n" );
			}
			case directive_op_desc::warning:
			{
				// Print a warning.
				//
				log<CON_YLW>( "Directive-time warning!!\n" );

				// Continue the translation from the right hand side.
				//
				return translate( sym, dir->rhs, bit_cnt );
			}
			default:
				unreachable();
		}

		// Failed translating the directive.
		//
		return {};
	}
};