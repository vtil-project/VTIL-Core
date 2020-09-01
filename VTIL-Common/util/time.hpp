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
#include <chrono>
#include <type_traits>
#include <array>
#include <string>
#include <thread>
#include "literals.hpp"
#include "type_helpers.hpp"
#include "zip.hpp"
#include "reverse_iterator.hpp"

// No-bloat chrono interface with some helpers and a profiler.
//
namespace vtil
{
	namespace time
	{
		// Declare basic units.
		//
		using hours =        std::chrono::hours;
		using minutes =      std::chrono::minutes;
		using seconds =      std::chrono::seconds;
		using milliseconds = std::chrono::milliseconds;
		using nanoseconds =  std::chrono::nanoseconds;
		using unit_t =       nanoseconds;

		using basic_units =                          std::tuple<  nanoseconds,   milliseconds,   seconds,   minutes,  hours   >;
		static constexpr std::array basic_unit_names =         { "nanoseconds", "milliseconds", "seconds", "minutes", "hours" };
		static constexpr std::array basic_unit_abbreviations = { "ns",          "ms",           "sec",     "min",     "hrs" };
		static constexpr std::array basic_unit_durations = make_constant_series<std::tuple_size_v<basic_units>>( [ ] ( auto x )
		{
			return std::chrono::duration_cast<unit_t>( std::tuple_element_t<decltype(x)::value, basic_units>( 1 ) );
		} );

		// Declare prefered clock and units.
		//
		using base_clock = std::chrono::steady_clock;
		using stamp_t =    base_clock::time_point;

		// Wrap around base clock.
		//
		static stamp_t now() { return base_clock::now(); }

		// Declare conversion to string.
		//
		template<Duration T>
		static std::string to_string( T duration )
		{
			// Convert to unit time.
			//
			unit_t t = std::chrono::duration_cast<unit_t>( duration );
			
			// Iterate duration list in descending order.
			//
			for ( auto [duration, abbrv] : backwards( zip( time::basic_unit_durations, time::basic_unit_abbreviations ) ) )
			{
				// If time is larger than the duration given or if we're at the last duration:
				//
				if ( t >= duration || duration == *std::begin( time::basic_unit_durations ) )
				{
					// Convert float to string.
					//
					char buffer[ 32 ];
					snprintf( buffer, 32, "%.2lf%s", t.count() / double( duration.count() ), abbrv );
					return buffer;
				}
			}
			unreachable();
		}
	};
	using timestamp_t = time::stamp_t;
	using timeunit_t =  time::unit_t;

	// Wrappers around std::this_thread::sleep_*.
	//
	template<Duration T>
	static void sleep_for( T&& d ) { std::this_thread::sleep_for( std::forward<T>( d ) ); }
	template<Timestamp T>
	static void sleep_until( T&& d ) { std::this_thread::sleep_until( std::forward<T>( d ) ); }

	// Times the callable given and returns pair [result, duration] if it has 
	// a return value or just [duration].
	//
	template<typename T, typename... Tx> requires InvocableWith<T, Tx...>
	static auto profile( T&& f, Tx&&... args )
	{
		using result_t = decltype( std::declval<T>()( std::forward<Tx>( args )... ) );

		if constexpr ( std::is_same_v<result_t, void> )
		{
			timestamp_t t0 = time::now();
			f( std::forward<Tx>( args )... );
			timestamp_t t1 = time::now();
			return t1 - t0;
		}
		else
		{

			timestamp_t t0 = time::now();
			result_t res = f();
			timestamp_t t1 = time::now();
			return std::make_pair( res, t1 - t0 );
		}
	}

	// Same as ::profile but ignores the return value and runs N times.
	//
	template<size_t N, typename T, typename... Tx> requires InvocableWith<T, Tx...>
	static timeunit_t profile_n( T&& f, Tx&&... args )
	{
		auto t0 = time::now();
		for ( size_t i = 0; i != N; i++ ) 
			f( args... ); // Not forwarded since we can't move N times.
		auto t1 = time::now();
		return t1 - t0;
	}
};