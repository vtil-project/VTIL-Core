#pragma once
#include <mutex>
#include <optional>
#include <capstone.hpp>

// The x86_reg value that equates to the first user-defined control register
// and a handy macro to get the value for Nth instance.
//
#define X86_REG_VCR(n) x86_reg( unsigned( X86_REG_ENDING ) + (n + 1) )
static constexpr x86_reg X86_REG_VCR0 = X86_REG_VCR( 0 );

namespace vtil::arch
{
	// Describes the properites of a user-defined control register.
	//
	struct control_register_desc
	{
		// Name of the register.
		//
		std::string identifier;

		// Whether this control register is read only or not.
		//
		bool read_only = false;
	};

	// Global list of control registers and the mutex protecting it.
	//
	static std::mutex control_register_list_mutex;
	static std::vector<control_register_desc> control_register_list;

	// Looks up the descriptor for the given control register.
	//
	static std::optional<control_register_desc> lookup_control_register( x86_reg reg )
	{
		std::lock_guard g( control_register_list_mutex );

		// Calculate the index and lookup the global list
		//
		size_t index = reg - X86_REG_VCR0;
		if ( control_register_list.size() <= index ) 
			return std::nullopt;
		return control_register_list[ index ];
	}

	// Creates a new control register based on the descriptor and returns the
	// x86_reg value that it is mapped to.
	//
	static x86_reg create_control_register( const control_register_desc& descriptor )
	{
		std::lock_guard g( control_register_list_mutex );

		// Calculate the index we will place this register at
		// push it up the list and then return the equivalent
		// x86_reg value
		//
		size_t index = control_register_list.size();
		control_register_list.push_back( descriptor );
		return X86_REG_VCR( index );
	}
};