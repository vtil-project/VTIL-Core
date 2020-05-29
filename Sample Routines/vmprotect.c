uint64_t test_entry_point( uint64_t r )
{
	 if ( r == 0x1337 )
		 return printf( "lol\n" );
	 volatile int a = 0x190C;
	 return ( ( r * 512 ) & ~a ) + 0x12c97f;
}