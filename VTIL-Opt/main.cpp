//#include "vtil-utils.hpp"

#include <vtil/compiler>

using namespace vtil;
using namespace logger;

int main(int argc, char** argv)
{
	if (argc < 3)
	{
		puts("Usage: opt in.vtil out.vtil");
		return EXIT_FAILURE;
	}
	auto input = argv[1];
	auto output = argv[2];

	auto rtn = load_routine(input);
	optimizer::apply_all_profiled(rtn);
	save_routine(rtn, output);
}