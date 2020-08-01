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
#include <vtil/arch>
#include <vtil/io>
#include <chrono>
#include <algorithm>
#include <functional>
#include <atomic>
#include <thread>
#include <future>
#include <vtil/symex>

// [Configuration]
// Determine whether or not to use parallel transformations and thread pooling.
//
#ifndef VTIL_OPT_USE_THREAD_POOLING
	#define VTIL_OPT_USE_PARALLEL_TRANSFORM true
#endif
#ifndef VTIL_OPT_USE_THREAD_POOLING
	#define VTIL_OPT_USE_THREAD_POOLING     true
#endif

namespace vtil::optimizer
{
	namespace impl
	{
		template<typename T>
		concept AtomicSummable = requires( std::atomic<size_t>& y, T x ) { y += x; };

		struct saved_cache 
		{ 
			symbolic::simplifier_state_ptr state = nullptr; 
			saved_cache() { }
			saved_cache( const saved_cache& o ) { fassert( !o.state ); }
		};
	};

	// Passes every block through the transformer given in parallel, returns the 
	// number of instances where this transformation was applied.
	//
	template<typename T, typename... Tx>
	static auto transform_parallel( routine* rtn, T&& fn, Tx&&... args )
	{
		using ret_type = decltype( fn( std::declval<basic_block*>(), std::declval<Tx&&>()... ) );

		// Declare worker and allocate the final result.
		//
		std::atomic<size_t> n = { 0 };
		auto worker = [ & ] ( basic_block* blk )
		{
			// If there's a valid cache saved, swap.
			//
			impl::saved_cache& cache = blk->context;
			symbolic::simplifier_state_ptr pcache = nullptr;
			if ( cache.state )
				pcache = symbolic::swap_simplifier_state( std::move( cache.state ) );

			// Execute.
			//
			if constexpr ( impl::AtomicSummable<ret_type> ) 
				n += fn( blk, args... );
			else
				fn( blk, args... );

			// Save current cache into the block.
			//
			cache.state = symbolic::swap_simplifier_state( std::move( pcache ) );
		};

		// If parallel transformation is disabled, use fallback.
		//
		if constexpr ( !VTIL_OPT_USE_PARALLEL_TRANSFORM )
		{
			rtn->for_each( worker );
		}
		// If thread pooling is enabled, use std::future.
		//
		else if constexpr ( VTIL_OPT_USE_THREAD_POOLING )
		{
			std::vector<std::future<void>> pool;
			pool.reserve( rtn->explored_blocks.size() );

			rtn->for_each( [ & ] ( basic_block* blk )
			{
				pool.emplace_back( std::async( std::launch::async, worker, blk ) );
			} );
		}
		// If thread pooling is disabled, use std::thread.
		//
		else
		{
			std::vector<std::thread> pool;
			pool.reserve( rtn->explored_blocks.size() );

			rtn->for_each( [ & ] ( auto* blk )
			{
				pool.emplace_back( worker, blk );
			} );

			std::for_each( pool.begin(), pool.end(), std::mem_fn( &std::thread::join ) );
		}

		// Return final result.
		//
		if constexpr( impl::AtomicSummable<ret_type> )
			return n.load();
	}

	// Declares a generic pass interface that any optimization pass implements.
	// - Passes should be always default constructable.
	//
	template<bool serial_execution = false>
	struct pass_interface
	{
		// Passes a single basic block through the optimizer, xblock will be set to true
		// if cross-block exploration is allowed.
		//
		virtual size_t pass( basic_block* blk, bool xblock = false ) = 0;

		// Passes every block through the optimizer with block refrences freely explorable,
		// returns the number of instances where this optimization was applied.
		//
		virtual size_t xpass( routine* rtn ) 
		{
			size_t n = 0;
			if constexpr ( serial_execution )
				rtn->for_each( [ & ] ( auto* blk ) { n += pass( blk, true ); } );
			else
				n = transform_parallel( rtn, [ & ] ( auto* blk ) { return pass( blk, true ); } );
			return n;
		}

		// Returns the name of the pass.
		//
		virtual std::string name() { return format::dynamic_type_name( *this ); }

		// Overload operator().
		//
		size_t operator()( basic_block* blk, bool xblock = false ) { return pass( blk, xblock ); }
		size_t operator()( routine* rtn ) { return xpass( rtn ); }
	};

	// Passes through each optimizer provided and returns the total number of optimizations applied.
	//
	template<typename... Tx>
	struct combine_pass;
	template<typename T>
	struct combine_pass<T> : T {};
	template<typename T1, typename... Tx>
	struct combine_pass<T1, Tx...> : pass_interface<>
	{
		size_t pass( basic_block* blk, bool xblock = false ) override
		{
			size_t n = T1{}.pass( blk, xblock );
			n += combine_pass<Tx...>{}.pass( blk, xblock );
			return n;
		}
		size_t xpass( routine* rtn ) override
		{
			size_t n = T1{}.xpass( rtn );
			n += combine_pass<Tx...>{}.xpass( rtn );
			return n;
		}
		std::string name() override { return "(" + T1{}.name() + " + " + combine_pass<Tx...>{}.name() + ")"; }
	};

	// Passes through first optimizer, if not no-op, passes through the rest.
	//
	template<typename T1, typename... Tx>
	struct conditional_pass : pass_interface<>
	{
		size_t pass( basic_block* blk, bool xblock = false ) override
		{
			if ( !xblock )
			{
				size_t n = T1{}.pass( blk, false );
				if ( n ) n += combine_pass<Tx...>{}.pass( blk, false );
				return n;
			}
			return T1{}.pass( blk, true );
		}
		size_t xpass( routine* rtn ) override
		{
			size_t n = T1{}.xpass( rtn );
			if ( n ) n += combine_pass<Tx...>{}.xpass( rtn );
			return n;
		}
		std::string name() override { return "conditional{" + T1{}.name() + " => " + combine_pass<Tx...>{}.name() + "}"; }
	};

	// Passes through each optimizer provided until the passes do not change the block.
	//
	template<typename... Tx>
	struct exhaust_pass : pass_interface<>
	{
		// Simple looping until pass returns 0.
		//
		size_t pass( basic_block* blk, bool xblock = false ) override
		{ 
			size_t cnt = 0;
			while ( size_t n = combine_pass<Tx...>{}.pass( blk, xblock ) )
				cnt += n;
			return cnt;
		}
		size_t xpass( routine* rtn ) override
		{
			size_t cnt = 0;
			while ( size_t n = combine_pass<Tx...>{}.xpass( rtn ) )
				cnt += n;
			return cnt;
		}
		std::string name() override { return "exhaust{" + combine_pass<Tx...>{}.name() + "}"; }
	};

	// Specializes the pass logic depending on whether it's restricted or not.
	//
	template<typename opt_lblock, typename opt_xblock>
	struct specialize_pass : pass_interface<>
	{
		size_t pass( basic_block* blk, bool xblock = false ) override
		{
			return xblock ? opt_xblock{}.pass( blk, true ) : opt_lblock{}.pass( blk, false );
		}
		size_t xpass( routine* rtn ) override
		{
			return opt_xblock{}.xpass( rtn );
		}
		std::string name() override { return "specialize{local=" + opt_lblock{}.name() + ", cross=" + opt_xblock{}.name() + "}"; }
	};

	// Forces logic pass to ignore cross-block.
	//
	template<typename T>
	struct local_pass : T
	{
		size_t pass( basic_block* blk, bool xblock = false ) override
		{
			return T::pass( blk, false );
		}
	};

	// Forces logic pass to return zero no matter what.
	//
	template<typename T>
	struct zero_pass : T
	{
		size_t pass( basic_block* blk, bool xblock = false ) override
		{
			T::pass( blk, xblock );
			return 0;
		}
	};

	// No-op pass.
	//
	struct nop_pass : pass_interface<>
	{
		size_t pass( basic_block* blk, bool xblock = false ) override { return 0; }
		size_t xpass( routine* rtn ) override { return 0; }
		std::string name() override { return "no-op"; }
	};

	// This wrapper spawns a new state of the given base type for each call
	// into pass and xpass letting the calls be const-qualified, can be used
	// for constexpr declarations.
	//
	template<typename T>
	struct spawn_state
	{
		// Imitate pass interface.
		//
		size_t pass( basic_block* blk, bool xblock = false ) const { return T{}.pass( blk, xblock ); }
		size_t xpass( routine* rtn ) const { return T{}.xpass( rtn ); }
		std::string name() { return T{}.name(); }

		// Overload operator().
		//
		size_t operator()( basic_block* blk, bool xblock = false ) const { return pass( blk, xblock ); }
		size_t operator()( routine* rtn ) const { return xpass( rtn ); }
	};

	// Dummy non-modifying wrapper.
	//
	template<typename T>
	struct nop_wrap : T
	{
		std::string name() override { return T{}.name(); }
	};

	// Used to profile the pass.
	//
	template<typename T>
	struct profile_pass : T
	{
		size_t pass( basic_block* blk, bool xblock = false ) override
		{
			if ( !xblock )
				logger::log( "Block %08x => %-64s |", blk->entry_vip, T{}.name() );
			auto t0 = std::chrono::steady_clock::now();
			size_t cnt = T::pass( blk, xblock );
			auto t1 = std::chrono::steady_clock::now();
			if ( !xblock )
				logger::log( " Took %-8.2fms (N=%d).\n", ( t1 - t0 ).count() * 1e-6f, cnt );
			return cnt;
		}

		size_t xpass( routine* rtn ) override
		{
			logger::log( "Routine => %-64s            |", T{}.name() );
			auto t0 = std::chrono::steady_clock::now();
			size_t cnt = T::xpass( rtn );
			auto t1 = std::chrono::steady_clock::now();
			logger::log( " Took %-8.2fms (N=%d).\n", ( t1 - t0 ).count() * 1e-6f, cnt );
			return cnt;
		}
	};

	// This wrapper applies a template modifier on each individual pass in the
	// given compound pass.
	//
	namespace impl
	{
		template<template<typename...> typename modifier, typename compound>
		struct apply_each_opt_t                                       { using type =     modifier<compound>; };

		template<template<typename...> typename modifier, typename compound>
		struct apply_each_opt_t<modifier, modifier<compound>>         { using type =     modifier<compound>; };

		template<template<typename...> typename modifier, typename... parts>
		struct apply_each_opt_t<modifier, spawn_state<parts...>>      { using type =     spawn_state<typename apply_each_opt_t<modifier, parts>::type...>;  };

		template<template<typename...> typename modifier, typename... parts>
		struct apply_each_opt_t<modifier, exhaust_pass<parts...>>     { using type =    exhaust_pass<typename apply_each_opt_t<modifier, parts>::type...>;  };

		template<template<typename...> typename modifier, typename... parts>
		struct apply_each_opt_t<modifier, combine_pass<parts...>>     { using type =    combine_pass<typename apply_each_opt_t<modifier, parts>::type...>;  };

		template<template<typename...> typename modifier, typename... parts>
		struct apply_each_opt_t<modifier, specialize_pass<parts...>>  { using type = specialize_pass<typename apply_each_opt_t<modifier, parts>::type...>;  };

		template<template<typename...> typename modifier, typename... parts>
		struct apply_each_opt_t<modifier, conditional_pass<parts...>> { using type = conditional_pass<typename apply_each_opt_t<modifier, parts>::type...>; };
	};

	template<template<typename...> typename modifier, typename compound>
	using apply_each = typename impl::apply_each_opt_t<modifier, compound>::type;
};