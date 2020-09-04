#include <vtil/arch>
#include <vtil/common>
#include <vtil/symex>
#include <filesystem>




#include "validation/pass_validation.hpp"
#include "validation/test1.hpp"

#include "common/interface.hpp"
#include "analysis/symbolic_analysis.hpp"


#include "common/apply_all.hpp"

#include "optimizer/symbolic/preliminary_register_elimination.hpp"


using namespace vtil;
using namespace vtil::logger;

void optimizer_test( routine* rtn )
{
	optimizer::bblock_extension_pass{}( rtn );
	optimizer::update_analysis<analysis::symbolic_analysis>{}( rtn );
	optimizer::preliminary_register_elimination{}( rtn );

	transform_parallel( rtn->explored_blocks, [ ] ( const std::pair<const vip_t, basic_block*>& e )
	{
		analysis::symbolic_analysis& a = e.second->context;

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