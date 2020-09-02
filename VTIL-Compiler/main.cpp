#include <vtil/arch>
#include <vtil/common>
#include <vtil/symex>
#include <filesystem>



using namespace vtil;
using namespace vtil::logger;



#include "validation/pass_validation.hpp"
#include "validation/test1.hpp"

#include "common/interface.hpp"
#include "analysis/symbolic_analysis.hpp"

void optimizer_test( routine* rtn )
{
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
		
		// Simplify and re-emit into the block.
		//
		a.prepare();
		a.reemit( e.second );
	} );
}

int main()
{
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

			/*
			for ( auto [vip, blk] : rtn->explored_blocks )
			{
				auto& sc = blk->context.get<analysis::symbolic_analysis>();
				for ( auto it = sc.segments.begin(); it != sc.segments.end(); it++ )
				{
					auto& seg = *it;

					log<CON_GRN>( "[Segment %s]\n", seg.segment_begin );

					log<CON_CYN>( "- # Memory Ops:   %d\n", seg.vm.memory_state.size() );
					log<CON_CYN>( "- # Register Ops: %d\n", seg.vm.register_state.size() );
					log<CON_YLW>( "- Stack pointer:  %s\n", seg.vm.register_state.read( REG_SP ) );

					switch ( seg.exit_reason )
					{
						case vm_exit_reason::stream_end:
							log<CON_BLU>( "Exit due to stream end\n" );

							if ( seg.is_branch_real )
							{
								if ( seg.segment_begin.block->next.empty() )
									log<CON_RED>( "Real Exit     " );
								else
									log<CON_RED>( "Real Call     " );
							}
							else                      log<CON_BLU>( "Virtual Branch" );
							log<CON_BRG>( " => " );
							if ( seg.branch_cc )
							{
								log<CON_YLW>( "%s", seg.branch_cc );            log<CON_BRG>( " ? " );
								log<CON_GRN>( "%s", seg.branch_targets[ 0 ] );  log<CON_BRG>( " : " );
								log<CON_RED>( "%s\n", seg.branch_targets[ 1 ] );
							}
							else
							{
								log<CON_PRP>( "%s\n", seg.branch_targets );
							}

							break;
						case vm_exit_reason::alias_failure:
							log<CON_RED>( "Exit due to alias analysis failure @" );
							log<CON_BRG>( " \"%s\"\n", std::next( it )->segment_begin->to_string() );

							break;
						case vm_exit_reason::high_arithmetic:
							log<CON_RED>( "Exit due to high arithmetic:\n" );
							break;
						case vm_exit_reason::unknown_instruction:
							log<CON_PRP>( "Exit due to non-symbolic instruction:\n" );
							break;
					}
					for ( auto& ins : seg.suffix )
						log<CON_YLW>( " + %s\n", ins );
				}
				log( "\n" );
			}
			*/

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