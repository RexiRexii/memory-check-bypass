#pragma once
#include <Windows.h>

#include <cstdint>
#include <vector>
#include <string>
#include <unordered_map>
#include <string_view>
#include <stdexcept>

// will log debug info, disable it if you want to use it on your module
constexpr auto debug_info = true;

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
	std::double_t time;
	std::uint8_t pad2[16];
	std::double_t time_spend;
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
	std::uintptr_t entry;
	secondary_hash_encryption enc;
	std::unordered_map<std::uintptr_t, std::size_t> hashes;

	active_hasher_t() : entry(0), enc(secondary_hash_encryption::unk_t), hashes({}) {}
};

namespace mem_scanner
{
	extern std::vector<std::uintptr_t> scan_pattern(std::string_view pattern, std::string_view mask, std::pair<std::uint32_t, std::uint32_t> scan_bounds);
	extern section_t get_section(std::string_view section, const bool clone);
}

namespace mem_utils
{
	// Other code that uses base on load requires this to be as a function
	__forceinline std::uintptr_t get_base()
	{
		static const auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleA(nullptr));
		return base;
	}

	template<typename ret, typename arg>
	__forceinline ret unbase(arg address, std::uintptr_t to_base = 0x400000)
	{
		return ret(address - to_base + get_base());
	}

	template<typename ret, typename arg>
	__forceinline ret rebase(arg address, std::uintptr_t to_base = 0x400000)
	{
		static const auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleA(nullptr));
		return ret(address - get_base() + to_base);
	}

	template<typename ...arg>
	void dbgprintf(const char* format, arg... args)
	{
		if constexpr (debug_info)
			printf(format, args...);
	}

	extern void console();
	extern void place_jmp(std::uintptr_t address, void* to, std::size_t nop_count = 0);
}