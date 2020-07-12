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
#include <vector>
#include <tuple>
#include "../directives/directive.hpp"

namespace vtil::symbolic::directive
{
	extern std::vector<std::pair<instance, instance>> boolean_simplifiers;
	extern const std::vector<std::pair<instance, instance>> boolean_joiners;

	const std::vector<std::pair<instance, instance>>& build_boolean_simplifiers();

    /*
    Auto generated using:

	int64_t test_values[] = {
		-3, -2, -1, 0, +1, +2, +3, 
				
		INT64_MAX - 1,
		INT64_MAX - 2,
		INT64_MAX - 3,
		INT64_MAX,  
		INT64_MIN + 1,
		INT64_MIN + 2,
		INT64_MIN + 3
	};

	math::operator_id cmpops[] = {
		math::operator_id::greater,
		math::operator_id::greater_eq,
		math::operator_id::equal,
		math::operator_id::not_equal,
		math::operator_id::less_eq,
		math::operator_id::less,
		math::operator_id::ugreater,
		math::operator_id::ugreater_eq,
		//math::operator_id::uequal,
		//math::operator_id::unot_equal,
		math::operator_id::uless_eq,
		math::operator_id::uless
	};
	math::operator_id cmbops[] = {
		math::operator_id::bitwise_and,
		math::operator_id::bitwise_or,
	};

	auto hypothesis_list = {
		std::array{ a, b,    a, c,    b, c,    a, b },
		std::array{ a, b,    c, a,    b, c,    a, b },
		std::array{ b, a,    a, c,    b, c,    a, b },
		std::array{ b, a,    c, a,    b, c,    a, b },
		std::array{ a, b,    a, c,    b, c+1,  a, b },
		std::array{ a, b,    c, a,    b, c+1,  a, b },
		std::array{ b, a,    a, c,    b, c+1,  a, b },
		std::array{ b, a,    c, a,    b, c+1,  a, b },
		std::array{ a, b,    a, c,    b, c-1,  a, b },
		std::array{ a, b,    c, a,    b, c-1,  a, b },
		std::array{ b, a,    a, c,    b, c-1,  a, b },
		std::array{ b, a,    c, a,    b, c-1,  a, b },
	};
	
	for ( auto [xa, xb, ya, yb, ha, hb, ra, rb] : hypothesis_list )
	{
		// Generate result set.
		//
		std::vector<symbolic::expression> results;
		for ( auto cmp : cmpops )
			results.push_back( symbolic::expression::make( ra, cmp, rb ) );
		results.push_back( { 1, 1 } );
		results.push_back( { 0, 1 } );

		// Pick 3 comparison, 1 combination operator.
		//
		for ( auto c0 : cmpops )
		{
			auto lhs = symbolic::expression::make( xa, c0, xb );
			for ( auto c1 : cmpops )
			{
				auto rhs = symbolic::expression::make( ya, c1, yb );
				for ( auto x : cmbops )
				{
					auto result_expression = symbolic::expression::make( lhs, x, rhs );
					for ( auto c2 : cmpops )
					{
						// Check if result is as expected if the condition is met.
						//
						bool holds = true;
						auto condition = symbolic::expression::make( ha, c2, hb );
						for ( auto& expected : results )
						{
							for ( auto va : test_values )
							{
								for ( auto vb : test_values )
								{
									for ( auto vc : test_values )
									{
										const auto eval = [ & ] ( const symbolic::unique_identifier& u ) -> std::optional<uint64_t>
										{
											if ( u == a.uid ) return va;
											if ( u == b.uid ) return vb;
											if ( u == c.uid ) return vc;
											unreachable();
										};

										if ( condition.evaluate( eval ).get<bool>().value_or( false ) )
										{
											holds &= *expected.evaluate( eval ).get<bool>() == *result_expression.evaluate( eval ).get<bool>();
										}
									}
								}
							}
							if ( !holds ) continue;

							// Add to the output.
							//
							logger::log( "{ %-64s __iff(%s, %s) },\n", result_expression.to_string() + ",", condition, expected );
						}
					}
				}
			}
		}
	}
    */
};