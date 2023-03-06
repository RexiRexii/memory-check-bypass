#include "utilities.hpp"

std::vector<std::uintptr_t> mem_scanner::scan_pattern(std::string_view pattern, std::string_view mask, std::pair<std::uint32_t, std::uint32_t> scan_bounds, int max_size)
{
	std::vector<std::uintptr_t> results_list = {};
	auto& [start_address, end_address] = scan_bounds;

	while (start_address < end_address)
	{
		auto matching = true;

		for (auto iter = 0; iter < mask.length(); iter++)
		{
			if (*reinterpret_cast<std::uint8_t*>(start_address + iter) != static_cast<std::uint8_t>(pattern[iter]) && mask[iter] == 'x')
			{
				matching = false;
				break;
			}
		}

		if (matching)
		{
			results_list.emplace_back(start_address);
			if (results_list.size() == max_size) break;
		}

		++start_address;
	}

	return results_list;
}

section_t mem_scanner::get_section(std::string_view section, const bool clone)
{
	section_t result = {0, 0, 0};

	auto segments_start = 0;
	const auto base = mem_utils::get_base();

	while (*reinterpret_cast<std::uint64_t*>(base + segments_start) != 0x000000747865742E) // .text section
		segments_start += 4;

	for (auto at = reinterpret_cast<segment_t*>(base + segments_start); (at->offset != 0 && at->size != 0); at++)
	{
		if (!std::strncmp(at->name, section.data(), section.length() + 1))
		{
			const auto offset = (base + at->offset);

			const auto clone_address = VirtualAlloc(nullptr, at->size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

			if (!clone_address)
				throw std::runtime_error("VirtualAlloc for clone failed");

			result.start = offset;
			result.size = at->size;

			// Only make a region clone if the user needs, vmp0 is not scanned and thus a clone is not needed
			if (clone)
			{
				result.clone = reinterpret_cast<std::uintptr_t>(clone_address);
				std::memcpy(reinterpret_cast<void*>(result.clone), reinterpret_cast<void*>(result.start), at->size);
			}
			else
				result.clone = 0;

			break;
		}
	}

	return result;
}

void mem_utils::console()
{
	const auto lib = LoadLibraryW(L"kernel32.dll");

	if (!lib)
		throw std::runtime_error("LoadLibraryW for kernel32.dll failed");

	const auto free_console = reinterpret_cast<std::uintptr_t>(GetProcAddress(lib, "FreeConsole"));

	if (free_console)
	{
		static auto jmp = free_console + 0x6;
		DWORD prot{0u};

		VirtualProtect(reinterpret_cast<void*>(free_console), 0x6, PAGE_EXECUTE_READWRITE, &prot);
		*reinterpret_cast<std::uintptr_t**>(free_console + 0x2) = &jmp;
		*reinterpret_cast<std::uint8_t*>(free_console + 0x6) = 0xC3;
		VirtualProtect(reinterpret_cast<void*>(free_console), 0x6, prot, &prot);
	}

	AllocConsole();

	FILE* file_stream;

	freopen_s(&file_stream, "CONIN$", "r", stdin);
	freopen_s(&file_stream, "CONOUT$", "w", stdout);
	freopen_s(&file_stream, "CONOUT$", "w", stderr);

	SetConsoleTitleA("meme check bypass by Rexi(us), Modul(us) and Pixle(us) sus!");
}

void mem_utils::place_jmp(std::uintptr_t address, void* to, std::size_t nop_count)
{
	DWORD prot{0u};
	VirtualProtect(reinterpret_cast<void*>(address), 5 + nop_count, PAGE_EXECUTE_READWRITE, &prot);

	*reinterpret_cast<std::uint8_t*>(address) = 0xE9;
	*reinterpret_cast<std::uintptr_t*>(address + 1) = reinterpret_cast<std::uintptr_t>(to) - address - 5;

	for (std::size_t i = 0; i < nop_count; i++)
		*reinterpret_cast<std::uint8_t*>(address + 5 + i) = 0x90;

	VirtualProtect(reinterpret_cast<void*>(address), 5 + nop_count, prot, &prot);
}
