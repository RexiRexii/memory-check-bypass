#pragma once
#include <Windows.h>

#include <cstdint>
#include <vector>
#include <string>
#include <unordered_map>
#include <string_view>
#include <stdexcept>
// utilities.hpp included everywhere so no need to make 3 or 4 calls to getmodulehandlea to get the same result.
const auto base = reinterpret_cast< std::uint32_t >( GetModuleHandleA( nullptr ) );

constexpr auto debug = true;

struct segment_t
{
	char name[8];
	std::size_t size;
	std::uintptr_t offset;
	std::uintptr_t pad0[6];
};

struct section_t
{
	std::uintptr_t start;
	std::uintptr_t clone;
	std::size_t size;
};

struct job_t
{
	std::uintptr_t* functions;
	std::uint8_t pad0[12];
	std::string name;
	std::uint8_t pad1[16];
	double time;
	std::uint8_t pad2[16];
	double time_spend;
	std::uint8_t pad3[8];
	std::uintptr_t state;
};

enum class secondary_hash_encryption
{
	unk_t,
	add_t,
	sub_t,
	xor_t,
};

struct active_hasher_t
{
	uintptr_t entry;
	secondary_hash_encryption enc;
	std::unordered_map<std::uintptr_t, std::size_t> hashes;

	active_hasher_t() : entry(0), enc(secondary_hash_encryption::unk_t), hashes({}) {}
};

namespace mem_scanner
{
	// no need to take c string as parameter here so changed to std::string_view								// scan bounds aren't going to be negative no reason to be signed.
	extern std::vector<std::uintptr_t> scan_pattern(std::string_view pattern, std::string_view mask, std::pair<std::uint32_t, std::uint32_t> scan_bounds);
	// std::string_view
	extern section_t get_section(std::string_view section, const bool clone);
}

namespace mem_utils
{
	template<typename ret, typename arg>
	ret unbase(arg address, std::uintptr_t to_base = 0x400000)
	{
		static const auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleA(nullptr));
		return ret((std::uintptr_t)(address)-to_base + base);
	}

	template<typename ret, typename arg>
	ret rebase(arg address, std::uintptr_t to_base = 0x400000)
	{
		static const auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleA(nullptr));
		return ret((std::uintptr_t)(address)-base + to_base);
	}

	template<typename arg>
	void dbgprintf(arg format, ...)
	{
		if constexpr (debug)
			printf(format);
	}

	extern void console();
	extern void place_jmp(std::uintptr_t address, void* to, std::size_t nop_count = 0);
}