#pragma once
#include <string>
#include <vector>
#include <keystone/keystone.h>
#pragma comment(lib, "keystone.lib")

namespace keystone
{
	struct context
	{
		ks_engine* handle = 0;
		void destroy() { ks_close( handle ); }

		operator ks_engine*() { return handle; }

		std::vector<uint8_t> operator()( const std::string& src, uint64_t va = 0 )
		{
			std::vector<uint8_t> out;

			size_t count;
			unsigned char* encode;
			size_t size;
			if ( ks_asm( handle, ( ".code64;" + src ).data(), va, &encode, &size, &count ) )
			{
				ks_free( encode );
				return {};
			}

			if ( size )
			{
				out = { encode, encode + size };
				ks_free( encode );
			}

			return out;
		}
	};

	static context create( ks_arch arch, ks_mode mode )
	{
		context ctx;
		if ( ks_open( arch, mode, &ctx.handle ) )
			throw "Failed to create the assembler!";
		return ctx;
	}
};

static auto assemble = keystone::create( KS_ARCH_X86, KS_MODE_64 );