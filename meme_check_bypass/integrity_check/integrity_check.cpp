#include "integrity_check.hpp"
#include <iostream>

#include <unordered_map>

memcheck_t::memcheck_t()
{
	this->text = mem_scanner::get_section(".text", true);
	this->rdata = mem_scanner::get_section(".rdata", true);
	this->vmpx = mem_scanner::get_section(".vmpx", true);
	this->vmp0 = mem_scanner::get_section(".vmp0", false);
	this->vmp1 = mem_scanner::get_section(".vmp1", true);

	const auto task_scheduler_pattern = mem_scanner::scan_pattern("\x55\x8B\xEC\x83\xE4\xF8\x83\xEC\x08\xE8\x00\x00\x00\x00\x8D\x0C\x24", "xxxxxxxxxx????xxx", { this->text.start, this->text.start + text.size + 0xF00000
})[0];

	this->task_scheduler = reinterpret_cast<std::uintptr_t(*)()>((task_scheduler_pattern + 14) + *reinterpret_cast<std::uint32_t*>(task_scheduler_pattern + 10))();
	this->task_scheduler_start = 308;
	this->task_scheduler_end = 312;
}

std::vector<active_hasher_t> populated_hashes;

std::uintptr_t core_hasher_start;
std::uintptr_t core_hasher_end;

std::uintptr_t esp_backup;
std::uintptr_t spoofed;

std::uintptr_t job_cache;
std::uintptr_t* old_vftable = 0;
std::uintptr_t new_vftable[6];

std::uintptr_t memcheck_t::get_job_by_name(const std::string& job_name) const
{
	auto iterator = *reinterpret_cast<const std::uintptr_t*>(this->task_scheduler + task_scheduler_start);
	const auto job_end = *reinterpret_cast<std::uintptr_t*>(this->task_scheduler + task_scheduler_end);

	while (iterator != job_end)
	{
		const auto inst = *reinterpret_cast<job_t**>(iterator);

		if (inst->name == job_name.c_str())
			return reinterpret_cast<std::uintptr_t>(inst);

		iterator += 8;
	}

	return 0;
}

std::uintptr_t* scan_for_regions(const memcheck_t* meme, std::pair<std::uintptr_t, std::uintptr_t> region, std::uintptr_t hasher_func)
{
	static const auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleA(nullptr));
	for (const auto& res : mem_scanner::scan_pattern("\x8B\x34\xBD\x00\x00\x00\x00", "xxx", region))
	{
		const auto mem = *reinterpret_cast<std::uintptr_t*>(res + 3);
		if (mem >= meme->vmpx.start && mem <= meme->vmpx.start + meme->vmpx.size)
		{
			const auto res = hasher_func + ((362085932 * *reinterpret_cast<std::uintptr_t*>(mem) - 854064575) ^ (-759031019 - 877351945 * *reinterpret_cast<std::uintptr_t*>(mem)));

			if (res == base + 0x1000)
				return reinterpret_cast<std::uintptr_t*>(mem);
		}
	}

	return 0;
}

std::size_t* scan_for_region_sizes(const memcheck_t* meme, std::pair<std::uintptr_t, std::uintptr_t> region, std::uintptr_t hasher_func, std::uintptr_t* region_list)
{
	static const auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleA(nullptr));
	for (const auto& res : mem_scanner::scan_pattern("\x8B\x14\xBD\x00\x00\x00\x00", "xxx", region))
	{
		const auto mem = *reinterpret_cast<std::uintptr_t*>(res + 3);
		if (mem >= meme->vmpx.start && mem <= meme->vmpx.start + meme->vmpx.size)
		{
			const auto res = ((362085932 * *reinterpret_cast<std::uintptr_t*>(mem) - 854064575) ^ (-759031019 - 877351945 * *reinterpret_cast<std::uintptr_t*>(mem)));
			
			const auto first_region = hasher_func + ((362085932 * region_list[0] - 854064575) ^ (-759031019 - 877351945 * region_list[0]));
			const auto second_region = hasher_func + ((362085932 * region_list[1] - 854064575) ^ (-759031019 - 877351945 * region_list[1]));

			if (res == second_region - first_region)
				return reinterpret_cast<std::size_t*>(mem);
		}
	}

	return 0;
}

bool bruteforce_encryption(std::uintptr_t checker, std::size_t original, std::uintptr_t hash_start, std::size_t hash_size, secondary_hash_encryption enc)
{
	for (std::size_t i = 0; i < 16; i++)
	{
		const auto hash_enc_t = reinterpret_cast<std::size_t(__cdecl*)(std::uintptr_t, std::uintptr_t, std::uintptr_t, std::uintptr_t)>(checker);
		const auto hash_enc = hash_enc_t(hash_start, hash_size, 0, i * 1236467);

		switch (enc)
		{
		case secondary_hash_encryption::add_t:
			if (hash_enc - i * 1236467 != original)
				return false;
			break;
		case secondary_hash_encryption::sub_t:
			if (hash_enc + i * 1236467 != original)
				return false;
			break;
		case secondary_hash_encryption::xor_t:
			if ((hash_enc ^ i * 1236467) != original)
				return false;
			break;
		default:
			return false;
		}
	}

	return true;
}

std::size_t __stdcall silent_hook(std::size_t hasher, std::uintptr_t start, std::uintptr_t size, std::uintptr_t _zero, std::uintptr_t key)
{
	mem_utils::dbgprintf("active hasher: %i\n", hasher);
	const auto active_hash_list = populated_hashes[hasher];

	mem_utils::dbgprintf("start wanted: %X - %X\n", start, mem_utils::rebase<std::uintptr_t>(start));
	mem_utils::dbgprintf("rest: %X - %X - %X\n", size, _zero, key);

	const auto cache = active_hash_list.hashes.find(start);

	if (cache == active_hash_list.hashes.end())
		mem_utils::dbgprintf("[debug -> silent checks] error\n");

	switch (active_hash_list.enc)
	{
	case secondary_hash_encryption::add_t:
		return cache->second + key;
	case secondary_hash_encryption::sub_t:
		return cache->second - key;
	case secondary_hash_encryption::xor_t:
		return cache->second ^ key;
	default:
		break;
	}

	return 0;
}

void __declspec(naked) silent_hook_fix()
{
	__asm
	{
		push[esp + 20];
		push[esp + 20];
		push[esp + 20];
		push[esp + 20];
		push[esp + 16];
		call silent_hook;
		add esp, 4;

		ret;
	}
}

std::uintptr_t __cdecl get_spoofed_address(std::uintptr_t address)
{
	if (address >= meme.text.start && address <= meme.text.start + meme.text.size)
		return address - meme.text.start + meme.text.clone;
	else if (address >= meme.rdata.start && address <= meme.rdata.start + meme.rdata.size)
		return address - meme.rdata.start + meme.rdata.clone;
	else if (address >= meme.vmpx.start && address <= meme.vmpx.start + meme.vmpx.size)
		return address - meme.vmpx.start + meme.vmpx.clone;
	else if (address >= meme.vmp1.start && address <= meme.vmp1.start + meme.vmp1.size)
		return address - meme.vmp1.start + meme.vmp1.clone;

	mem_utils::dbgprintf("[debug -> core] no clone for %X (%X)\n", mem_utils::rebase<std::uintptr_t>(address), address);
	return address;
}

__declspec(naked) void main_hasher_loop()
{
	__asm
	{
		mov esp_backup, esp;
		sub esp, 0x300;

		pushad;

		push ebx;
		call get_spoofed_address;
		add esp, 4;

		mov spoofed, eax;

		popad;

		add esp, 0x300;
		mov eax, spoofed;
		mov esp, eax;

	hasher_start:

		mov eax, [esp];
		add eax, ebx;
		imul eax, 0x1594FE2D;
		add eax, edi;
		rol eax, 0x13;
		imul edi, eax, 0x0CBB4ABF7;

		lea eax, [ebx + 4];
		sub eax, [esp + 4];
		add ebx, 8;
		add esp, 8;
		imul eax, 0x344B5409;
		add eax, [ebp - 0x10];
		rol eax, 0x11;
		imul eax, 0x1594FE2D;
		mov[ebp - 0x10], eax;

		mov eax, [esp];
		xor eax, ebx;
		add ebx, 4;
		add esp, 4;
		imul eax, 0x1594FE2D;
		add eax, [ebp - 0xC];
		rol eax, 0xD;
		imul eax, 0x0CBB4ABF7;
		mov[ebp - 0xC], eax;

		mov eax, [esp];
		sub eax, ebx;
		add ebx, 4;
		add esp, 4;
		imul eax, 0x344B5409;
		add eax, esi;
		rol eax, 0xF;
		imul esi, eax, 0x1594FE2D;

		cmp ebx, ecx;
		jb hasher_start;

		mov esp, esp_backup;

		jmp[core_hasher_end];
	}
}

std::uintptr_t __fastcall job_hook(std::uintptr_t _this, std::uintptr_t junk, std::uintptr_t a2)
{
	*reinterpret_cast<std::uintptr_t**>(job_cache) = old_vftable;

	mem_utils::place_jmp(core_hasher_start, main_hasher_loop);
	
	for (std::size_t i = 0; i < populated_hashes.size(); i++)
	{
		const auto& hasher_info = populated_hashes[i];

		DWORD old_protect, new_protect;
		VirtualProtect(reinterpret_cast<void*>(hasher_info.entry), 2, PAGE_EXECUTE_READWRITE, &old_protect);

		*reinterpret_cast<std::uint8_t*>(hasher_info.entry) = 0x6A;
		*reinterpret_cast<std::uint8_t*>(hasher_info.entry + 1) = i;

		VirtualProtect(reinterpret_cast<void*>(hasher_info.entry), 2, old_protect, &new_protect);

		mem_utils::place_jmp(hasher_info.entry + 2, silent_hook_fix);
	}

	const auto hook_t = reinterpret_cast<std::uintptr_t(__thiscall*)(std::uintptr_t, std::uintptr_t)>(old_vftable[5]);
	const auto hook_vft = hook_t(_this, a2);

	return hook_vft;
}

void memcheck_t::initialize_bypass() const
{
	mem_utils::dbgprintf("text region: %X - %X\n", meme.text.start, meme.text.size);
	mem_utils::dbgprintf("rdata region: %X - %X\n", meme.rdata.start, meme.rdata.size);
	mem_utils::dbgprintf("vmp1 region: %X - %X\n", meme.vmp1.start, meme.vmp1.size);

	auto hasher_func = mem_scanner::scan_pattern("\x0F\xB6\x45\xFF\x69\xC0\xCC\xCC\xCC\xCC\x5F", "xxxxxxxxxxx", std::pair<int32_t, int32_t>(this->text.start, this->text.start + text.size))[0];

	if (!hasher_func)
		mem_utils::dbgprintf("[debug -> core] couldn't grab hasher function\n");

	bool found_hasher_func = false;
	hasher_func += 16 - (hasher_func % 16);

	for (std::size_t i = 0; i < 2; i++)
	{
		if (*reinterpret_cast<std::uint8_t*>(hasher_func) == 0x55 || *reinterpret_cast<std::uint8_t*>(hasher_func + 1) == 0x8B || *reinterpret_cast<std::uint8_t*>(hasher_func + 2) == 0xEC)
		{
			found_hasher_func = true;
			break;
		}

		hasher_func += 16;
	}

	const auto region_list = scan_for_regions(this, std::pair<std::uintptr_t, std::uintptr_t>(this->vmp0.start, this->vmp0.start + this->vmp0.size), hasher_func);

	if (!region_list)
		scan_for_regions(this, std::pair<std::uintptr_t, std::uintptr_t>(this->text.start, this->text.start + this->text.size), hasher_func);

    const auto region_sizes = scan_for_region_sizes(this, std::pair<std::uintptr_t, std::uintptr_t>(this->vmp0.start, this->vmp0.start + this->vmp0.size), hasher_func, region_list);

	if (!region_sizes)
		scan_for_region_sizes(this, std::pair<std::uintptr_t, std::uintptr_t>(this->text.start, this->text.start + this->text.size), hasher_func, region_list);

	core_hasher_start = mem_scanner::scan_pattern("\x8B\x03\x03\xC3\x69\xC0\x2D\xFE\x94\x15", "x????xxx", { this->text.start, this->text.start + text.size })[0];
	core_hasher_end = (core_hasher_start + 107);

	std::vector<std::uintptr_t> silent_checkers {};

	int count = 0;
	for (auto& res : mem_scanner::scan_pattern("\x0F\xBE\x00\xFE", "xx?x", { this->text.start, this->text.start + this->text.size }))
	{
		bool possible = false;

		if (mem_scanner::scan_pattern("\x0F\xBE\x00\xFF", "xx?x", { res, res + 50 }).size() == 1 || mem_scanner::scan_pattern("\x0F\xBE\x00\xEF", "xx?x", { res, res + 50 }).size() == 1)
			possible = true;

		if (possible)
		{
			auto entry = res - (res % 16);

			for (std::size_t i = 0; i < 5; i++)
			{
				if (*reinterpret_cast<std::uint8_t*>(entry) == 0x55 || *reinterpret_cast<std::uint8_t*>(entry + 1) == 0x8B || *reinterpret_cast<std::uint8_t*>(entry + 2) == 0xEC)
				{
					if (mem_scanner::scan_pattern("\x8D\x00\x02", "x?x", { entry, res }).size()
						&& mem_scanner::scan_pattern("\x8B\x00\x0C", "x?x", { entry, res }).size() 
						&& mem_scanner::scan_pattern("\x8B\x00\x08", "x?x", { entry, res }).size())
					{
						mem_utils::dbgprintf("[debug -> core] %i secondary size: %X\n", ++count, mem_utils::rebase<uintptr_t>(entry));

						silent_checkers.push_back(entry);
					}
				}

				entry -= 16;
			}
		}
	}

	if (silent_checkers.size() != 16)
		mem_utils::dbgprintf("[debug -> silent checks] couldn't grab the correct amount of silent checkers.\n");

	if (!populated_hashes.size())
	{
		populated_hashes.reserve(16);

		for (const auto silent_checker : silent_checkers)
		{
			active_hasher_t hasher{};
			hasher.entry = silent_checker;

			for (std::size_t i = 0; i < 30; i++)
			{
				const auto hash_start = hasher_func + ((362085932 * region_list[i] - 854064575) ^ (-759031019 - 877351945 * region_list[i]));
				const auto hash_size = ((362085932 * region_sizes[i] - 854064575) ^ (-759031019 - 877351945 * region_sizes[i]));

				const auto hash_t = reinterpret_cast<std::size_t(__cdecl*)(std::uintptr_t, std::uintptr_t, std::uintptr_t, std::uintptr_t)>(silent_checker);
				const auto hash = hash_t(hash_start, hash_size, 0, 0);

				if (hash_size > 0 && hasher.enc == secondary_hash_encryption::unk_t)
				{
					if (bruteforce_encryption(silent_checker, hash, hash_start, hash_size, secondary_hash_encryption::add_t))
						hasher.enc = secondary_hash_encryption::add_t;
					else if (bruteforce_encryption(silent_checker, hash, hash_start, hash_size, secondary_hash_encryption::sub_t))
						hasher.enc = secondary_hash_encryption::sub_t;
					else if (bruteforce_encryption(silent_checker, hash, hash_start, hash_size, secondary_hash_encryption::xor_t))
						hasher.enc = secondary_hash_encryption::xor_t;
					else
						mem_utils::dbgprintf("[debug -> core] failed to grab hash type");
				}

				mem_utils::dbgprintf("[debug -> core] hash start: %X\n", hash_start);
				hasher.hashes[hash_start] = hash;
			}

			populated_hashes.push_back(hasher);
		}
	}

	const auto job = this->get_job_by_name("US14116_pt2");
	std::memcpy(new_vftable, *reinterpret_cast<void**>(job), sizeof(std::uintptr_t) * 6);

	old_vftable = *reinterpret_cast<std::uintptr_t**>(job);
	new_vftable[5] = reinterpret_cast<std::uintptr_t>(job_hook);

	*reinterpret_cast<std::uintptr_t**>(job) = new_vftable;
	job_cache = job;
}