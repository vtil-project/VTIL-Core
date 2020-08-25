#pragma once
#include <thread>
#include <future>
#include <optional>
#include <memory>
#include "type_helpers.hpp"

// [Configuration]
// Determine whether or not to use thread pooling for tasks.
//
#ifndef VTIL_USE_THREAD_POOLING
	#define VTIL_USE_THREAD_POOLING     true
#endif

namespace vtil::task
{
	// Declare task controller.
	//
	struct task_controller
	{
		inline static thread_local std::vector<std::function<void( bool make_or_break )>> callbacks = {};
		
		// Simple ::begin and ::end helpers that go through all callbacks.
		//
		static void begin() 
		{
			for ( auto& cb : callbacks )
				cb( true );
		}
		static void end() 
		{
			for ( auto& cb : callbacks )
				cb( false );
		}
	};

	// Declare task local, must always have the following signature:
	//
	template<typename T>
	struct alignas( T ) local_variable
	{
		// Hold the value.
		//
		union
		{
			T value;
			uint8_t raw[ sizeof( T ) ];
		};

		// Whether variable is initialized or not.
		//
		bool init = false;

		// Holds the default value.
		//
		const std::optional<T> default_value;

		// Adds a callback to the task controller.
		//
		local_variable( std::optional<T> default_value = std::nullopt )
			: raw{ 0 }, default_value( std::move( default_value ) )
		{
			task_controller::callbacks.emplace_back( [ this ] ( bool make )
			{
				if ( make ) get();
				else        reset();
			} );
		}

		// Initializes / deinitializes where necessary.
		//
		T* get()
		{
			if ( !std::exchange( init, true ) )
			{
				if ( default_value )
				{
					if constexpr ( std::is_copy_constructible_v<T> )
						return new ( &value ) T( default_value.value() );
				}
				else
				{
					if constexpr ( std::is_default_constructible_v<T> )
						return new ( &value ) T();
				}
				unreachable();
			}
			return &value;
		}
		void reset()
		{
			if ( std::exchange( init, false ) )
				std::destroy_at( &value );
		}

		// Steals current state.
		//
		T steal()
		{
			T x = std::move( *get() );
			reset();
			return x;
		}

		// Simple accessors.
		//
		T& operator*() { return *get(); }
		T* operator->() { return get(); }

		// Deinitialize on destroy.
		//
		~local_variable() { reset(); }
	};
	#define task_local( ... ) thread_local vtil::task::local_variable<__VA_ARGS__> 

	// Declare handle type.
	// 
#if VTIL_USE_THREAD_POOLING
	using handle_type = std::future<void>;
#else
	using handle_type = std::thread;
#endif

	// Task instance.
	//
	struct instance
	{
		handle_type handle;

		// Construct by invocable.
		//
		template<typename T> requires Invocable<T, void>
		instance( T&& fn )
		{
			// Wrap around task markers.
			//
			auto f = [ fn = std::forward<T>( fn ) ]() 
			{ 
				task_controller::begin();
				fn(); 
				task_controller::end();
			};

#if VTIL_USE_THREAD_POOLING
			handle = std::async( std::launch::async, std::move( f ) );
#else
			handle = { f };
#endif
		}

		// Default move / copy.
		//
		instance( instance&& ) = default;
		instance( const instance& ) = default;
		instance& operator=( instance&& ) = default;
		instance& operator=( const instance& ) = default;

		// Destruction calls ::get if pooling is enabled to 
		// propagate exceptions from std::future.
		//
		~instance()
		{
#if VTIL_USE_THREAD_POOLING
			handle.get();
#else
			handle.join();
#endif
		}
	};
};