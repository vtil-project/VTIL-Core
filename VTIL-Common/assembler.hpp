#pragma once
#include <string>
#include <vector>

// Simple wrapper around Keystone disassembler.
//
struct ks_struct;
namespace keystone
{
	ks_struct* get_handle();
	std::vector<uint8_t> assemble( const std::string& src, uint64_t va = 0 );
};
