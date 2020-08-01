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
#pragma once
#include <vtil/math>
#include <vtil/utility>
#include <set>
#include "unique_identifier.hpp"
#include "../directives/expression_signature.hpp"

// [Configuration]
// Determine the number of x value keys we use to estimate values.
//
#ifndef VTIL_SYMEX_XVAL_KEYS
	#define VTIL_SYMEX_XVAL_KEYS 4
#endif

// Allow expression::reference to be used with expression type directly as operable.
//
namespace vtil::symbolic { struct expression; struct expression_reference; };
namespace vtil::math { template<> struct resolve_alias<symbolic::expression_reference> { using type = symbolic::expression; }; };

namespace vtil::symbolic
{
	struct expression;

	// Expression delegates used to implement copyless write detection 
	// in case the reference is already owning.
	//
	struct expression_delegate
	{
		shared_reference<expression>& ref;
		bool dirty;

		expression_delegate( shared_reference<expression>& ref ) : ref( ref ), dirty( false ) {}
		expression_delegate( const expression_delegate& ) = delete;
		expression_delegate& operator=( const expression_delegate& ) = delete;

		template<typename T, std::enable_if_t<!std::is_same_v<std::decay_t<T>, expression_delegate>, int> = 0>
		expression_delegate& operator=( T&& value )
		{
			ref = std::forward<T>( value );
			dirty = true;
			return *this;
		}

		const expression* operator->() const { return ref.get(); }
		const expression& operator*() const { return *ref.get(); }
		expression* operator+() { dirty = 1; return ref.own(); }
	};

	// Expression references.
	//
	struct expression_reference : shared_reference<expression>
	{
		// Declare hasher and equivalence checker.
		//
		struct hasher
		{
			size_t operator()( const expression_reference& value ) const noexcept { return value.hash(); }
		};
		struct if_equal
		{
			bool operator()( const expression_reference& v1,
							 const expression_reference& v2 ) const noexcept { return v1.equals( *v2 ); }
		};
		struct if_identical
		{
			bool operator()( const expression_reference& v1,
							 const expression_reference& v2 ) const noexcept { return v1.is_identical( *v2 ); }
		};

		// Forward operators and constructor.
		//
		template<typename... Tx>
		expression_reference( Tx&&... args ) 
			: shared_reference( std::forward<Tx>( args )...) {}

		using shared_reference::operator bool;
		using shared_reference::operator*;
		using shared_reference::operator+;
		using shared_reference::operator->;

		// Basic comparison operators are redirected to the pointer type.
		//
		bool operator<( const shared_reference& o ) const { return combined_value < o.combined_value; }
		bool operator==( const shared_reference& o ) const { return combined_value == o.combined_value; }
		bool operator<( const expression_reference& o ) const { return combined_value < o.combined_value; }
		bool operator==( const expression_reference& o ) const { return combined_value == o.combined_value; }

		// Implement some helpers to conditionally copy.
		//
		expression_reference& make_lazy();
		expression_reference& simplify( bool prettify = false, bool* out = nullptr );
		expression_reference& resize( bitcnt_t new_size, bool signed_cast = false, bool no_explicit = false );
		[[nodiscard]] expression_reference make_lazy() const;
		[[nodiscard]] expression_reference simplify( bool prettify = false, bool* out = nullptr ) const;
		[[nodiscard]] expression_reference resize( bitcnt_t new_size, bool signed_cast = false, bool no_explicit = false ) const;

		// Forward declared redirects for internal use cases.
		//
		hash_t hash() const;
		bool is_simple() const;
		void update( bool auto_simplify );

		// Equivalence check.
		//
		bool equals( const expression& exp ) const;
		bool is_identical( const expression& exp ) const;

		// Implemented for sinkhole use.
		//
		bitcnt_t size() const;

		// Implemented for logger use.
		//
		std::string to_string() const;

		// Transforms the whole tree according to the functor, much more optimized compared to expression::transform.
		//
		template<typename T>
		bool transform_single( const T& func, bool auto_simplify, bool do_update );
		template<typename T>
		[[nodiscard]] std::pair<bool, expression_reference> transform_single( const T& func, bool auto_simplify, bool do_update ) const
		{
			auto copy = make_copy( *this );
			return { copy.transform_single( func, auto_simplify, do_update ), std::move( copy ) };
		}

		template<typename T>
		bool transform_rec( const T& func, bool bottom, bool auto_simplify );
		template<typename T>
		[[nodiscard]] std::pair<bool, expression_reference> transform_rec( const T& func, bool bottom, bool auto_simplify ) const
		{
			auto copy = make_copy( *this );
			return { copy.transform_rec( func, bottom, auto_simplify ), std::move( copy ) };
		}

		// Implement original transform signature.
		//
		template<typename T>
		expression_reference& transform( const T& func, bool bottom = false, bool auto_simplify = true )
		{
			transform_rec( func, bottom, auto_simplify );
			return *this;
		}
		template<typename T>
		expression_reference transform( const T& func, bool bottom = false, bool auto_simplify = true ) const
		{
			return std::move( make_copy( *this ).transform( func, bottom, auto_simplify ) );
		}
	};

	// Expression descriptor.
	//
	struct expression : math::operable<expression>
	{
		using delegate =           expression_delegate;
		using reference =          expression_reference;
		using weak_reference =     weak_reference<expression>;
		using uid_relation_table = std::vector<std::pair<expression::weak_reference, expression::weak_reference>>;

		// If symbolic variable, the unique identifier that it maps to.
		//
		unique_identifier uid = {};

		// If operation, identifier of the operator and the sub-expressions for the operands.
		//
		math::operator_id op = math::operator_id::invalid;
		reference lhs = {};
		reference rhs = {};

		// An arbitrarily defined complexity value that is used as an inverse reward function in simplification.
		//
		double complexity = 0;

		// Depth of the current expression.
		// - If constant or symbolic variable, = 0
		// - Otherwise                         = max(operands...) + 1
		//
		size_t depth = 0;

		// Hash of the expression used by the simplifier cache.
		//
		hash_t hash_value = {};

		// Signature of the expression.
		//
		expression_signature signature = {};

		// Whether expression passed the simplifier already or not, note that this is a hint and there may 
		// be cases where it already has passed it and this flag was not set. Albeit those cases will most 
		// likely not cause performance issues due to the caching system.
		//
		mutable bool simplify_hint = false;

		// Disables implicit auto-simplification for the expression if is set.
		//
		bool is_lazy = false;

		// Default constructor and copy/move.
		//
		expression() = default;
		expression( expression&& exp ) = default;
		expression( const expression & exp ) = default;
		expression& operator=( expression&& exp ) = default;
		expression& operator=( const expression & exp ) = default;

		// Construct from constants.
		//
		template<Integral T = uint64_t>
		expression( T value, bitcnt_t bit_count = sizeof( T ) * 8 ) : operable( value, bit_count ), simplify_hint( true ) { update( false ); }

		// Constructor for symbolic variables.
		//
		expression( const unique_identifier& uid, bitcnt_t bit_count ) : operable(), uid( uid ), simplify_hint( true ) { value = math::bit_vector( bit_count ); update( false ); }

		// Constructor for expressions.
		//
		expression( math::operator_id op, const reference& rhs ) : operable(), op( op ), rhs( rhs ) { update( true ); }
		expression( math::operator_id op, reference&& rhs      ) : operable(), op( op ), rhs( std::move( rhs ) ) { update( true ); }
		expression( const reference& lhs, math::operator_id op, const reference& rhs ) : operable(), op( op ), lhs( lhs ), rhs( rhs ) { update( true ); }
		expression( reference&& lhs,      math::operator_id op, const reference& rhs ) : operable(), op( op ), lhs( std::move( lhs ) ), rhs( rhs ) { update( true ); }
		expression( const reference& lhs, math::operator_id op, reference&& rhs      ) : operable(), op( op ), lhs( lhs ), rhs( std::move( rhs ) ) { update( true ); }
		expression( reference&& lhs,      math::operator_id op, reference&& rhs      ) : operable(), op( op ), lhs( std::move( lhs ) ), rhs( std::move( rhs ) ) { update( true ); }

		// Alternate "constructors" for internal use for the sake of having control over auto-simplification of user-reaching expressions.
		//
		template<typename A>
		static expression make( math::operator_id op, A&& op1 )
		{
			expression exp = {};
			exp.op = op;
			exp.rhs = std::forward<A>( op1 );
			exp.update( false );
			return exp;
		}

		template<typename A, typename B>
		static expression make( A&& op1, math::operator_id op, B&& op2 )
		{
			expression exp = {};
			exp.op = op;
			exp.lhs = std::forward<A>( op1 );
			exp.rhs = std::forward<B>( op2 );
			exp.update( false );
			return exp;
		}

		// Wrapper around math::descriptor_of()
		//
		const math::operator_desc& get_op_desc() const { return math::descriptor_of( op ); };

		// Helpers to determine the type of the expression.
		//
		bool is_variable() const { return uid; }
		bool is_expression() const { return op != math::operator_id::invalid; }
		bool is_unary() const { return is_expression() && get_op_desc().operand_count == 1; }
		bool is_binary() const { return is_expression() && get_op_desc().operand_count == 2; }
		bool is_valid() const { return is_expression() || is_variable() || is_constant(); }
		explicit operator bool() const { return is_valid(); }

		// Returns the cached hash value to abide the standard vtil::hashable.
		//
		hash_t hash() const { return hash_value; }

		// Returns the number of constants used in the expression.
		//
		size_t count_constants() const;

		// Returns the number of variables used in the expression.
		//
		size_t count_variables() const;

		// Returns the number of unique variables used in the expression.
		//
		size_t count_unique_variables( std::set<unique_identifier>* visited = nullptr ) const;

		// Updates the expression state.
		//
		expression& update( bool auto_simplify );

		// Converts to human-readable format.
		//
		std::string to_string() const;

		// Resizes the expression, if not constant, expression::resize will try to propagate 
		// the operation as deep as possible.
		//
		expression& resize( bitcnt_t new_size, bool signed_cast = false, bool no_explicit = false );

		// Simplifies and optionally prettifies the expression.
		//
		expression& simplify( bool prettify = false );

		// Returns whether the given expression is identical to the current instance.
		// - Note: basic comparison opeators should not be overloaded since expression is of type
		//         math::operable and that would create multiple meanings.
		//
		bool is_identical( const expression& other ) const;

		// Returns whether the given expression is equivalent to the current instance.
		// - This routine tries to match the simplified forms whereas ::is_identical will try to 
		//   match the operators operands and uids one to one.
		//
		bool equals( const expression& other ) const;

		// Returns whether the given expression is matching the current instance, if so returns
		// the UID relation table, otherwise returns nullopt.
		//
		std::optional<uid_relation_table> match_to( const expression& other, bool same_depth ) const;

		// Calculates the x values.
		//
		std::array<uint64_t, VTIL_SYMEX_XVAL_KEYS> xvalues() const;

		// Evaluates the expression invoking the callback passed for unknown variables,
		// this avoids copying of the entire tree and any simplifier calls so is preferred
		// over *transform(...).get().
		//
		template<typename T>
		math::bit_vector evaluate( T&& lookup ) const
		{
			// If value is known, return as is.
			//
			if ( value.is_known() ) 
				return value;
		
			// If variable:
			//
			if ( is_variable() )
			{
				// If lookup helper passed and succesfully finds the value, use as is.
				//
				if ( std::optional<uint64_t> res = lookup( uid ) )
					return { *res, size() };
			
				// Otherwise return unknown.
				//
				return value;
			}

			// Try to evaluate the result and return.
			//
			math::bit_vector result = {};
			if ( is_unary() )
				result = math::evaluate_partial( op, {},                      rhs->evaluate( lookup ) );
			else if ( is_binary() )
				result = math::evaluate_partial( op, lhs->evaluate( lookup ), rhs->evaluate( lookup ) );
			return result;
		}
		
		// Implement math::operable::get with evaluator.
		//
		static constexpr auto default_eval = [ ] ( const unique_identifier& v ) { return std::nullopt; };
		template<typename type>
		std::optional<type> get() const { return evaluate( default_eval ).get<type>(); }
		template<bool as_signed = false, typename type = std::conditional_t<as_signed, int64_t, uint64_t>>
		std::optional<type> get() const { return evaluate( default_eval ).get<type>(); }

		// Enumerates the whole tree.
		//
		template<typename T>
		const expression& enumerate( const T& fn, bool bottom = false ) const
		{
			if ( bottom )
			{
				if ( lhs ) lhs->enumerate( fn, bottom );
				if ( rhs ) rhs->enumerate( fn, bottom );
				fn( *this );
			}
			else
			{
				fn( *this );
				if ( lhs ) lhs->enumerate( fn, bottom );
				if ( rhs ) rhs->enumerate( fn, bottom );
			}
			return *this;
		}

		// Disables simplifications for the expression (and it's future parents) 
		// when set, can be reset by ::simplify().
		//
		expression& make_lazy() { is_lazy = true; return *this; }

		// Force the inlining of the destructor.
		//
		__forceinline ~expression() {}
	};

	// Boxed expression solves the aforementioned problem by creating a type that can be 
	// used for the storage of an expression in a way that it is meant to be comparable.
	//
	struct boxed_expression : expression 
	{
		using reference = shared_reference<boxed_expression>;

		// Gently wrap around expression.
		//
		boxed_expression() = default;
		boxed_expression( expression&& o ) : expression( std::move( o ) ) {};
		boxed_expression( const expression& o ) : expression( o ) {};
		boxed_expression( boxed_expression&& o ) = default;
		boxed_expression( const boxed_expression& o ) = default;
		boxed_expression& operator=( boxed_expression&& o ) = default;
		boxed_expression& operator=( const boxed_expression& o ) = default;

		// Explicit function to decay back to expression type.
		//
		expression& decay() { return *this; }
		const expression& decay() const { return *this; }

		// Implement comparison operators.
		//
		bool operator==( const boxed_expression& o ) const { return is_identical( o ); }
		bool operator!=( const boxed_expression& o ) const { return !is_identical( o ); }
		bool operator<( const boxed_expression& o )  const { return hash() < o.hash(); }
	};


	// Transforms the whole tree according to the functor, much more optimized compared to expression::transform.
	//
	template<typename T>
	bool expression_reference::transform_single( const T& func, bool auto_simplify, bool do_update )
	{
		// Save original hash.
		//
		hash_t hash_0 = hash();

		// Invoke via delegate.
		//
		expression_delegate del = { *this };
		func( del );

		// If function did not modify the value:
		//
		if ( !del.dirty )
		{
			// If simple already or no auto simplifiy set, return false.
			//
			if ( !auto_simplify || is_simple() )
				return false;

			// Invoke simplifier and return its state as "did-change".
			//
			bool simplified;
			simplify( false, &simplified );
			return simplified;
		}

		// Invoke update if not done already.
		//
		if ( hash_0 != hash() && do_update )
			update( auto_simplify );
		// If done but we still need to auto-simplify:
		//
		else if ( auto_simplify && !is_simple() )
			simplify();

		// Report changed.
		//
		return true;
	}
	template<typename T>
	bool expression_reference::transform_rec( const T& func, bool bottom, bool auto_simplify )
	{
		const auto transform_children = [ & ] ()
		{
			// If RHS exists:
			//
			bool changed = false;
			if ( auto& rhs = get()->rhs )
			{
				// Recursively transform RHS, if changed:
				//
				if ( auto [crhs, nrhs] = rhs.transform_rec( func, bottom, auto_simplify ); crhs )
				{
					// Set changed, own self and update node, transform LHS if exists.
					//
					auto owning = own();
					changed = true;
					owning->rhs = nrhs;
					if ( auto& lhs = owning->lhs )
						( bool ) lhs.transform_rec( func, bottom, auto_simplify );
				}
				// If not, but LHS exists:
				//
				else if ( auto& lhs = get()->lhs )
				{
					// Recursively transform LHS, if changed:
					//
					if ( auto [clhs, nlhs] = lhs.transform_rec( func, bottom, auto_simplify ); clhs )
					{
						// Set changed, own self and update node.
						//
						changed = true;
						own()->lhs = nlhs;
					}
				}
			}
			return changed;
		};

		if ( bottom )
		{
			// Transform all children.
			//
			bool changed = transform_children();

			// If changed, update the expression.
			//
			if( changed )
				own()->update( auto_simplify );
			
			// Transform self and return.
			//
			return changed | transform_single( func, auto_simplify, true );
		}
		else
		{
			// Transform self without updating if auto_simplify is not set.
			//
			bool changed = transform_single( func, auto_simplify, false );

			// Transform all children, if any of them were changed or if
			// auto simplify was not set causing us to delay the update
			// together with a change in current node, update self.
			//
			if ( transform_children() | ( changed && !auto_simplify ) )
			{
				own()->update( auto_simplify );
				changed = true;
			}

			// Return final state.
			//
			return changed;
		}
	}
};