#include "../include/Stockholm.hpp"

int main(int argc, char** argv)
{
	if (argc > 4)
	{
		std::cerr << "Error: too many arguments." << std::endl;
		Stockholm::help();
		return 1;
	}

	std::vector<std::string> args;
	for (int i = 1; i < argc; i++)
	{
		std::string arg = argv[i];
		std::erase_if(arg, ::isspace);
		args.push_back(arg);
	}

	if (argc == 2)
	{
		if (args[0] == "-h" || args[0] == "--help")
		{
			Stockholm::help();
			return 0;
		}
		else if (args[0] == "-v" || args[0] == "--version")
		{
			Stockholm::version();
			return 0;
		}
	}

	try
	{
		Stockholm stockholm;
		stockholm.parse_arg(argc, args);

		if (stockholm.isReverse())
			stockholm.wannaUnlock();
		else
			stockholm.wannaLock();
	}
	catch(const std::exception& e)
	{
		std::cerr << "Error: " << e.what() << std::endl;
		Stockholm::help();
		return 1;
	}

	return 0;
}
