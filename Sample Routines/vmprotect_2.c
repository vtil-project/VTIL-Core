#pragma pack(push, 1)
struct much_complex_object
{
	uint32_t a;
	uint8_t b;
	uint8_t c;
	uint16_t d;

	__declspec( noinline ) int32_t wow()
	{
		return c * b + a;
	}
};
#pragma pack(pop)

__declspec( dllexport, noinline ) uint64_t test_entry_point( uint64_t r )
{
	much_complex_object wow = {
		r & 0xFF00FF00,
		(r >> 16) % 0xA3,
		r & 0x000000FF,
		uint16_t( r * r )
	};

	volatile int lol = wow.wow();
	if ( printf( "{%d}!\n", lol ) && lol < 5 )
		return wow.a & ~lol + 0x3545fa1;

	for ( int i = 0; i < 4; i++ )
		lol = ( ( lol ^ i ) * 0x100003B );
	
	return lol;
}