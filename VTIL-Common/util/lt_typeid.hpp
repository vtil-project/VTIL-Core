#pragma once
#include <type_traits>
#include <stdint.h>

namespace vtil
{
	// This class generates unique 64-bit hash for each type at link time 
	// with no dependency on compiler features such as RTTI.
	//
	template<typename T>
	class lt_typeid
	{
		// Invoked internally to calculate the final hash.
		//
		static size_t calculate()
		{
			// Calculate the distance between the static identifier we store 
			// and the function and apply an aribtrary hash function over it. 
			// This should match for all identical binaries regardless of 
			// any relocation where relevant.
			//
			intptr_t reloc_delta = ( intptr_t ) &calculate - ( intptr_t ) &value;

			// Apply an arbitrary hash function to the relocation delta.
			//
			return ( 0x47C63F4156E0EA7F ^ reloc_delta ) * ( reloc_delta | 3 );
		}
	public:
		// Stores the computed hash at process initialization time.
		//
		inline static const size_t value = calculate();
	};
};