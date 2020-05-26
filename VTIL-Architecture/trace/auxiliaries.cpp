#include "auxiliaries.hpp"

namespace vtil
{
	// Checks if the instruction given accesses the variable, optionally filtering to the
	// access type specified, tracer passed will be used to generate pointers when needed.
	//
	access_details test_access( const il_const_iterator& it, const symbolic::variable::descriptor_t& var, tracer* tracer, access_type type )
	{
		// If variable is of register type:
		//
		if ( auto reg = std::get_if<symbolic::variable::register_t>( &var ) )
		{
			// Iterate each operand:
			//
			for ( int i = 0; i < it->base->operand_count(); i++ )
			{
				// Skip if not register.
				//
				if ( !it->operands[ i ].is_register() )
					continue;

				// Skip if access type does not match.
				//
				switch ( type )
				{
					// ::read will filter to read or read/write.
					//
					case access_type::read:
						if ( it->base->operand_types[ i ] == operand_type::write )
							continue;
						break;
					// ::write will filter to write or read/write. 
					//
					case access_type::write:
						if ( it->base->operand_types[ i ] < operand_type::write )
							continue;
						break;
					// ::readwrite will filter to only read/write.
					//
					case access_type::readwrite:
						if ( it->base->operand_types[ i ] != operand_type::readwrite )
							continue;
						break;
					// ::none accepts any access.
					//
					case access_type::none:
						break;
				}

				// Skip if no overlap.
				//
				auto& ref_reg = it->operands[ i ].reg();
				if ( !ref_reg.overlaps( *reg ) )
					continue;

				// Return access details.
				//
				access_type type_found;
				if ( it->base->operand_types[ i ] == operand_type::readwrite )
					type_found = access_type::readwrite;
				else if ( it->base->operand_types[ i ] == operand_type::write )
					type_found = access_type::write;
				else
					type_found = access_type::read;

				return {
					type_found,
					ref_reg.bit_offset - reg->bit_offset,
					ref_reg.bit_count
				};
			}
		}
		// If variable is of memory type:
		//
		else if( auto mem = std::get_if<symbolic::variable::memory_t>( &var ) )
		{
			// If instruction accesses memory:
			//
			if ( it->base->accesses_memory() )
			{
				// Skip if access type does not match.
				//
				switch ( type )
				{
					// ::read will filter to read.
					//
					case access_type::read:
						if ( it->base->writes_memory() )
							return { access_type::none };
						break;
					// ::write will filter to write. 
					//
					case access_type::write:
						if ( !it->base->writes_memory() )
							return { access_type::none };
						break;
					// Read/write does not exist for memory operations.
					//
					case access_type::readwrite:
						unreachable();
					// ::none accepts any access.
					//
					case access_type::none:
						// Determine the type and set it.
						//
						type = it->base->writes_memory() ? access_type::write : access_type::read;
						break;
				}

				// Generate an expression for the pointer.
				//
				auto [base, offset] = it->get_mem_loc();
				symbolic::pointer ptr = { tracer->trace( { it, base } ) + offset };

				// If the two pointers can overlap (not restrict qualified against each other):
				//
				if ( ptr.can_overlap( mem->base ) )
				{
					// If it can be expressed as a constant:
					//
					if ( auto disp = ( ptr - mem->base ) )
					{
						// Check if within boundaries:
						//
						int64_t low_offset = *disp;
						int64_t high_offset = low_offset + it->access_size();
						if ( low_offset < ( mem->bit_count / 8 ) && high_offset > 0 )
						{
							// Can safely multiply by 8 and shrink to bitcnt_t type from int64_t 
							// since variables are of maximum 64-bit size which means both offset
							// and size will be small numbers.
							//
							return {
								type,
								bitcnt_t( low_offset * 8 ),
								bitcnt_t( ( high_offset - low_offset ) * 8 )
							};
						}
					}
					// Otherwise, return unknown.
					//
					else
					{
						return { type, 0, -1 };
					}
				}
			}
		}

		// No access case.
		//
		return { access_type::none };
	}
};