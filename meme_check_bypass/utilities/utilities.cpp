#include "utilities.hpp"

std::vector<std::uintptr_t> mem_scanner::scan_pattern(const char* pattern, const char* mask, std::pair<std::int32_t, std::int32_t> scan_bounds)
{
	std::vector<std::uintptr_t> results_list = {};

	auto bounds = std::get<0>(scan_bounds);

	while (bounds < std::get<1>(scan_bounds))
	{
		auto matching = true;

		for (auto iter = 0; iter < std::strlen(mask); iter++)
		{
			if (*reinterpret_cast<std::uint8_t*>(bounds + iter) != static_cast<std::uint8_t>(pattern[iter]) && mask[iter] == 'x')
			{
				matching = false;
				break;
			}
		}

		if (matching)
			results_list.emplace_back(bounds);

		bounds++;
	}

	return results_list;
}

section_t mem_scanner::get_section(const std::string& section, const bool clone)
{
	section_t result = { 0, 0, 0 };

	const auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleA(nullptr));
	auto segments_start = 0;

	while (*reinterpret_cast<std::uint64_t*>(base + segments_start) != 0x000000747865742E) // .text section
		segments_start += 4;

	for (auto at = reinterpret_cast<segment_t*>(base + segments_start); (at->offset != 0 && at->size != 0); at++)
	{
		if (!std::strncmp(at->name, section.c_str(), section.length() + 1))
		{
			const auto offset = (base + at->offset);

			result.start = offset;
			result.size = at->size;
			result.clone = reinterpret_cast<uintptr_t>(VirtualAlloc(nullptr, at->size, MEM_COMMIT, PAGE_READWRITE));

			if (clone && result.clone)
				std::memcpy(reinterpret_cast<void*>(result.clone), reinterpret_cast<void*>(result.start), at->size);

			break;
		}
	}

	return result;
}

void mem_utils::console()
{
	const auto lib = LoadLibraryW(L"kernel32.dll");
	const auto free_console = reinterpret_cast<std::uintptr_t>(GetProcAddress(lib, "FreeConsole"));

	if (free_console)
	{
		static auto jmp = free_console + 0x6;
		DWORD old{};

		VirtualProtect(reinterpret_cast<void*>(free_console), 0x6, PAGE_EXECUTE_READWRITE, &old);
		*reinterpret_cast<std::uintptr_t**>(free_console + 0x2) = &jmp;
		*reinterpret_cast<std::uint8_t*>(free_console + 0x6) = 0xC3;
		VirtualProtect(reinterpret_cast<void*>(free_console), 0x6, old, &old);
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
	DWORD old_protect, new_protect;
	VirtualProtect(reinterpret_cast<void*>(address), 5 + nop_count, PAGE_EXECUTE_READWRITE, &old_protect);

	*reinterpret_cast<std::uint8_t*>(address) = 0xE9;
	*reinterpret_cast<std::uintptr_t*>(address + 1) = reinterpret_cast<std::uintptr_t>(to) - address - 5;

	for (std::size_t i = 0; i < nop_count; i++)
		*reinterpret_cast<std::uint8_t*>(address + 5 + i) = 0x90;

	VirtualProtect(reinterpret_cast<void*>(address), 5 + nop_count, old_protect, &new_protect);
}