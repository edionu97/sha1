#include <iostream>

#include "Hasher/sha1_hasher.h"

int main()  // NOLINT(bugprone-exception-escape)
{
	sha1_hasher hasher{};

	hasher.update("g");
	hasher.update("r");
	hasher.update("a");
	hasher.update("p");
	hasher.update("e");

	std::cout << hasher.get_final() << "\n\n\n";

	for(const auto& value: hasher.compute_multiple_sha1("gr", { "ape", "adle", "andma", "ape" }))
	{
		std::cout << value << '\n';
	}

	return 0;
}

