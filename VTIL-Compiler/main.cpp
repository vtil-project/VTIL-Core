#include <vtil/arch>
#include <vtil/common>
#include <vtil/symex>
#include <filesystem>




#include "validation/pass_validation.hpp"
#include "validation/test1.hpp"

#include "common/interface.hpp"
#include "analysis/symbolic_analysis.hpp"


#include "common/apply_all.hpp"


namespace vtil::optimizer
{
	struct symbolic_dce : pass_interface<>
	{
		size_t pass( basic_block* blk, bool xblock )
		{
			analysis::symbolic_analysis& sblk = blk->context;

			size_t cnt = 0;

			// For each segment:
			//
			for ( auto it = sblk.segments.begin(); it != sblk.segments.end(); ++it )
			{
				// For each register:
				//
				for ( auto& [reg, ctx] : it->register_state )
				{
					// Skip if stack pointer and volatile registers.
					//
					if ( reg.flags & ( register_stack_pointer | register_volatile ) )
						continue;

					// Create a visit list and recursive alive-check.
					//
					std::unordered_map<il_const_iterator, uint64_t> visit_list;
					auto get_used_mask = [ & ]( auto&& self,
												const analysis::symbolic_analysis& blk,
												std::list<analysis::symbolic_segment>::const_iterator it,
												const register_desc::weak_id& id ) -> uint64_t
					{
						// If at the end, propagate:
						//
						if ( it == blk.end() )
						{
							// TODO DO THIS PROPERLY
							uint64_t rmask = 0;
							uint64_t vmask = math::fill( 64 );
							symbolic::variable var = { register_desc{ id, 64, 0 } };
							if ( auto access = var.accessed_by( std::prev( blk.begin()->segment_begin.block->end() ) ) )
							{
								if ( access.read )
									rmask |= math::fill( access.bit_count, access.bit_offset ) & vmask;
								if ( access.write )
									vmask &= ~math::fill( access.bit_count, access.bit_offset );
							}

							if ( !vmask )
								return rmask;

							for ( auto& next : blk.segments.front().segment_begin.block->next )
							{
								const analysis::symbolic_analysis& nblk = next->context;
								rmask |= self( self, nblk, nblk.segments.begin(), id ) & vmask;
							}
							return rmask;
						}

						// Check visit cache, return if already inserted.
						//
						auto [vit, inserted] = visit_list.emplace( it->segment_begin, 0ull );
						uint64_t vmask = math::fill( 64 );
						uint64_t& rmask = vit->second;
						if ( !inserted )
							return rmask;

						// Iterate until last segment:
						//
						for ( ; it != blk.segments.end(); ++it )
						{
							// If read from, add to read mask.
							//
							auto rit = it->register_references.find( id );
							if ( rit != it->register_references.end() )
								rmask |= rit->second & vmask;

							// If written to, remove from vmask.
							//
							auto wit = it->register_state.value_map.find( id );
							if ( wit != it->register_state.value_map.end() )
							{
								math::bit_enum( wit->second.bitmap, [ &, vmask = std::ref( vmask ) ] ( bitcnt_t n )
								{
									vmask &= ~math::fill( wit->second.linear_store[ n ].size(), n );
								} );
							}

							// If used as is or if completely overwritten return.
							//
							if ( !vmask )
								return rmask;

							// Apply same heuristic for suffix:
							//
							bitcnt_t msb = math::msb( vmask ) - 1;
							bitcnt_t lsb = math::lsb( vmask ) - 1;
							symbolic::variable var = { register_desc{ id, msb - lsb + 1, lsb } };
							for ( auto& sfx : it->suffix )
							{
								if ( auto access = var.accessed_by( sfx ) )
								{
									if ( access.read )
										rmask |= math::fill( access.bit_count, access.bit_offset ) & vmask;
									if ( access.write )
										vmask &= ~math::fill( access.bit_count, access.bit_offset );
								}
							}
						}

						// If used as is or if completely overwritten return.
						//
						if ( !vmask )
							return rmask;

						// Invoke propagation.
						//
						rmask |= vmask & self( self, blk, blk.segments.end(), id );
						return rmask;
					};
					auto rmask = get_used_mask( get_used_mask, sblk, std::next( it ), reg );

					// TODO: Fix, does not handle partial discard.
					//
					symbolic::context::segmented_value& vctx = ctx;
					math::bit_enum( ctx.bitmap, [ & ] ( bitcnt_t n )
					{
						if ( !( math::fill( vctx.linear_store[ n ].size(), n ) & rmask ) )
						{
							math::bit_reset( vctx.bitmap, n );
							vctx.linear_store[ n ] = nullptr;
							cnt++;
						}
					} );
				}
			}

			return cnt;
		}
	};
};


using namespace vtil;
using namespace vtil::logger;

void optimizer_test( routine* rtn )
{
	optimizer::bblock_extension_pass{}( rtn );

	transform_parallel( rtn->explored_blocks, [ ] ( const std::pair<const vip_t, basic_block*>& e )
	{
		analysis::symbolic_analysis& a = e.second->context;

		// Run simple dce.
		//
		for ( auto it = a.segments.begin(); it != a.segments.end(); ++it )
		{
			for ( auto kit = it->register_state.value_map.begin(); kit != it->register_state.value_map.end(); )
			{
				bool used = false;
				if ( kit->first.flags & register_local )
				{
					for ( auto& seg : make_range( std::next( it ), a.segments.end() ) )
					{
						auto it = seg.register_references.find( kit->first );
						if ( used = it != seg.register_references.end() && it->second & kit->second.bitmap )
							break;

						bitcnt_t write_msb = math::msb( kit->second.bitmap ) - 1;
						bitcnt_t write_size = kit->second.linear_store[ write_msb ].size() + write_msb;
						register_desc k = { kit->first, write_size };

						for ( auto& sfx : seg.suffix )
							if ( used = symbolic::variable{ k }.read_by( sfx ) )
								break;
					}
				}
				else
				{
					used = true;
				}

				if ( !used )
					kit = it->register_state.value_map.erase( kit );
				else
					++kit;
			}
		}
	} );

	while ( size_t n = optimizer::symbolic_dce{}( rtn ) );

	transform_parallel( rtn->explored_blocks, [ ] ( const std::pair<const vip_t, basic_block*>& e )
	{
		analysis::symbolic_analysis& a = e.second->context;

		for ( auto it = a.segments.begin(); it != a.segments.end(); ++it )
		{
			for ( auto kit = it->register_state.value_map.begin(); kit != it->register_state.value_map.end(); )
			{
				if ( !kit->second.bitmap )
					kit = it->register_state.value_map.erase( kit );
				else
					++kit;
			}
		}

		// Simplify and re-emit into the block.
		//
		a.prepare();
		a.reemit( e.second );
	} );
}

int main()
{
	// Test validity.
	//
	bool success = optimizer::validation::test1{}( optimizer_test );
	if ( success ) log<CON_GRN>( "Passed validation.\n" );
	else error( "Validation failed." );

	// Test performance.
	//
	for( int i = 0; i < 100; i++ )
	{
		double total_inst = 0;
		timeunit_t total_time = 0ns;

		for ( auto& file : std::filesystem::directory_iterator( "S:\\VTIL-Playground"s ) )
		{
			if ( file.path().extension() != ".vtil" || file.path().filename().string().ends_with( "new.vtil" ) )
				continue;

			auto rtn = std::unique_ptr<routine>{ load_routine( file ) };

			log( "Optimizing %s...\n", file.path().filename() );
			int64_t ins = rtn->num_instructions();
			int64_t blks = rtn->num_blocks();

			auto duration = profile( [ & ] () { optimizer_test( rtn.get() ); } );

			int64_t oins = rtn->num_instructions();
			int64_t oblks = rtn->num_blocks();
		
			log<CON_YLW>( " - Time taken:        %s\n", duration );
			log<CON_CYN>( " - Block count:       %-5d => %-5d (%.2f%%).\n", blks, oblks, 100.0f * float( float( oblks - blks ) / blks ) );
			log<CON_CYN>( " - Instruction count: %-5d => %-5d (%.2f%%).\n", ins, oins, 100.0f * float( float( oins - ins ) / ins ) );

			total_time += duration;
			total_inst += ins;

			auto new_file = file.path();
			new_file.replace_extension( "new" + new_file.extension().string() );
			log( "Saving as %s\n\n", new_file.filename() );
			save_routine( rtn.get(), new_file );
		}

		log( CON_GRN, "Time spent per instruction:  %s\n", total_time / total_inst );
		log( CON_YLW, " - %.2fk ins / sec\n", ( total_inst * 1s / total_time ) / 1000.0f );
		log( CON_YLW, " - %.2fm ins / min\n", ( total_inst * 1min / total_time ) / 1000000.0f );
	}

	sleep_for( 10min );

	return 0;
}