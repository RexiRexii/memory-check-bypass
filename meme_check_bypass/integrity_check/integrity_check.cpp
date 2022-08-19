#include "integrity_check.hpp"
#include <iostream>

#include <unordered_map>

memcheck_t::memcheck_t()
{
	this->text = mem_scanner::get_section(".text", true);
	this->rdata = mem_scanner::get_section(".rdata", true);
	this->vmpx = mem_scanner::get_section(".vmpx", true);
	this->vmp0 = mem_scanner::get_section(".vmp0", false); // Not cloned, nont scanned, needed in checks
	this->vmp1 = mem_scanner::get_section(".vmp1", true);

	const auto task_scheduler_pattern = mem_scanner::scan_pattern("\x55\x8B\xEC\x83\xE4\xF8\x83\xEC\x08\xE8\x00\x00\x00\x00\x8D\x0C\x24", "xxxxxxxxxx????xxx", { this->text.start, this->text.start + text.size })[0];

	this->task_scheduler = reinterpret_cast<std::uintptr_t(*)()>((task_scheduler_pattern + 14) + *reinterpret_cast<std::uint32_t*>(task_scheduler_pattern + 10))();
	this->task_scheduler_start = 308;
	this->task_scheduler_end = 312;
}

std::vector<active_hasher_t> populated_hashes; // List of all secondary hashers and their hashes

std::uintptr_t core_hasher_start;
std::uintptr_t core_hasher_end;

// These 2 variables are just a lazy way of storing values for the main hasher bypass.
std::uintptr_t esp_backup;
std::uintptr_t spoofed;

// Save data for the job hook which is restored after 1 call.
std::uintptr_t job_cache;
std::uintptr_t* old_vftable = 0;
std::uintptr_t new_vftable[6];

std::uintptr_t memcheck_t::get_job_by_name(std::string_view job_name) const
{
	auto iterator = *reinterpret_cast<const std::uintptr_t*>(this->task_scheduler + task_scheduler_start);
	const auto job_end = *reinterpret_cast<std::uintptr_t*>(this->task_scheduler + task_scheduler_end);

	while (iterator != job_end)
	{
		const auto inst = *reinterpret_cast<job_t**>(iterator);

		if (inst->name == job_name.data())
			return reinterpret_cast<std::uintptr_t>(inst);

		iterator += 8;
	}

	return 0;
}

// Simple function to decrypt the result of a hasher region start address and size.
// Taken straight from disassembly!
std::size_t decrypt_region_result(std::size_t entry)
{
	return ((362085932 * entry - 854064575) ^ (-759031019 - 877351945 * entry));
}

// Scan for the integrity check hasher regions
std::uintptr_t* scan_for_regions(const memcheck_t* meme, std::pair<std::uintptr_t, std::uintptr_t> region, std::uintptr_t hasher_func)
{
	static const auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleA(nullptr));

	// Scan for a move instruction of a possible region start.
	// Instruction scanned for is:
	//     mov     esi, ds:dword_XXXXXXXX[edi*4]
	// Sig: 8B 34 BD ?? ?? ?? ??
	// The extra unknowns are ommited during scan but are
	//    present in the comment for the sake of visuals.
	for (const auto& res : mem_scanner::scan_pattern("\x8B\x34\xBD\x00\x00\x00\x00", "xxx", region))
	{
		// Only actually try to get the result of the pointer
		//     IF the result is within the ".vmpx" region.
		const auto mem = *reinterpret_cast<std::uintptr_t*>(res + 3);
		if (mem >= meme->vmpx.start && mem <= meme->vmpx.start + meme->vmpx.size)
		{
			const auto res = hasher_func + decrypt_region_result(*reinterpret_cast<std::uintptr_t*>(mem));

			// Make sure the region obtained is the start of the integrity check zones
			if (res == base + 0x1000)
				return reinterpret_cast<std::uintptr_t*>(mem);
		}
	}

	return 0;
}

std::size_t* scan_for_region_sizes(const memcheck_t* meme, std::pair<std::uintptr_t, std::uintptr_t> region, std::uintptr_t hasher_func, std::uintptr_t* region_list)
{
	static const auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleA(nullptr));

	// Scan for a move instruction of a possible region start.
	// Instruction scanned for is:
	//     mov     edx, ds:dword_XXXXXXXX[edi*4]
	// Sig: 8B 14 BD ?? ?? ?? ??
	// The extra unknowns are ommited during scan but are
	//    present in the comment for the sake of visuals.
	for (const auto& res : mem_scanner::scan_pattern("\x8B\x14\xBD\x00\x00\x00\x00", "xxx", region))
	{
		// Only actually try to get the result of the pointer
		//     IF the result is within the ".vmpx" region.
		const auto mem = *reinterpret_cast<std::uintptr_t*>(res + 3);
		if (mem >= meme->vmpx.start && mem <= meme->vmpx.start + meme->vmpx.size)
		{
			const auto res = decrypt_region_result(*reinterpret_cast<std::uintptr_t*>(mem));

			const auto first_region = hasher_func + decrypt_region_result(region_list[0]);
			const auto second_region = hasher_func + decrypt_region_result(region_list[1]);

			// Check if the first entry is the same size as the space between
			//   the integrity check first and second regions.
			if (res == second_region - first_region)
				return reinterpret_cast<std::size_t*>(mem);
		}
	}

	return 0;
}

// Takes a checker and the original hash and tries to get the math operation used.
secondary_hash_encryption bruteforce_encryption(std::uintptr_t checker, std::size_t original, std::uintptr_t hash_start, std::size_t hash_size)
{
	uint8_t enc_type = 7; // 111

	for (std::size_t i = 0; i < 16; i++)
	{
		const int res = i * 1236467; // Some large number to try and prevent collisions as much as possible

		const auto hash_enc_t = reinterpret_cast<std::size_t(__cdecl*)(std::uintptr_t, std::uintptr_t, std::uintptr_t, std::uintptr_t)>(checker);
		const auto hash_enc = hash_enc_t(hash_start, hash_size, 0, res);

		if ((enc_type & 1) && hash_enc - res != original) // 001
			enc_type &= ~1; // add

		if ((enc_type & 2) && hash_enc + res != original) // 010
			enc_type &= ~2; // sub

		if ((enc_type & 4) && (hash_enc ^ res) != original) // 100
			enc_type &= ~4; // xor
	}

	// Switch based on the binary result left over
	switch (enc_type)
	{
	case 1: // 001
		return secondary_hash_encryption::add_t;
	case 2: // 010
		return secondary_hash_encryption::sub_t;
	case 4: // 100
		return secondary_hash_encryption::xor_t;
	}

	return secondary_hash_encryption::unk_t;
}

// Main hook that is called when a secondary hasher is called
std::size_t __stdcall silent_hook(std::size_t hasher, std::uintptr_t start, std::uintptr_t size, std::uintptr_t _zero, std::uintptr_t key)
{
	// We pass the current hasher id as the first parameter, use that to get the current hash list.
	const auto& active_hash_list = populated_hashes[ hasher ];
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

// This loader stub is used before invoking our main secondary hasher hook
//   because we pushed an additional argument after the original call instruction
//   and thus need to repush all arguments and fix stack before returning.
//   (or do stupid stack manipulation)
void __declspec(naked) silent_hook_fix()
{
	__asm
	{
		// Repeated +20 to keep argument
		//   order the same.
		push[esp + 20];
		push[esp + 20];
		push[esp + 20];
		push[esp + 20];

		// If we were to push +20 here too we would push the return address
		//   instead of the hasher id we pushed because we push the id after
		//   the original call instruction.
		push[esp + 16];
		call silent_hook;
		add esp, 4; // Remove the id we pushed before returning.

		ret;
	}
}

// Either returns a cloned region or the original address if it did not exist.
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

// This is the main hasher loop hook,
//   takes an address and returns the cloned
//   address if it exists.
__declspec(naked) void main_hasher_loop()
{
	__asm
	{
		// A special note here is before the main loop is invoked,
		//   all registers are backed up and if a register is modified
		//   to a different value than expected, the user gets flagged and kicked.
		// This simply gets out of the backed up register region
		//   and saves all registers before we call our spoof address getter.
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

// This is the main job hook that is used to apply our hooks on the task scheduler.
std::uintptr_t __fastcall job_hook(std::uintptr_t _this, std::uintptr_t junk, std::uintptr_t a2)
{
	// Remove our hook as it is no longer needed,
	//   we just needed a single sweep on the task
	//   scheduler to safely apply our hook.
	*reinterpret_cast<std::uintptr_t**>(job_cache) = old_vftable;

	// Main hasher hook
	mem_utils::place_jmp(core_hasher_start, main_hasher_loop);

	// For each secondary hasher, place a "push ID" before
	//   the jump to our hook to allow our hook to know
	//   which hasher list to grab during the lookup.
	for (std::size_t i = 0; i < populated_hashes.size(); i++)
	{
		const auto& hasher_info = populated_hashes[i];

		DWORD prot;
		VirtualProtect(reinterpret_cast<void*>(hasher_info.entry), 2, PAGE_EXECUTE_READWRITE, &prot);

		// push ID
		*reinterpret_cast<std::uint8_t*>(hasher_info.entry) = 0x6A;
		*reinterpret_cast<std::uint8_t*>(hasher_info.entry + 1) = i;

		VirtualProtect(reinterpret_cast<void*>(hasher_info.entry), 2, prot, &prot);

		// Place the jump after the "push ID"
		mem_utils::place_jmp(hasher_info.entry + 2, silent_hook_fix);
	}

	// Call the old job function before returning to allow a clean pass.
	const auto hook_t = reinterpret_cast<std::uintptr_t(__thiscall*)(std::uintptr_t, std::uintptr_t)>(old_vftable[5]);
	const auto hook_vft = hook_t(_this, a2);

	return hook_vft;
}

void memcheck_t::initialize_bypass() const
{
	mem_utils::dbgprintf("[debug -> core] text region: %X - %X\n", meme.text.start, meme.text.size);
	mem_utils::dbgprintf("[debug -> core] rdata region: %X - %X\n", meme.rdata.start, meme.rdata.size);
	mem_utils::dbgprintf("[debug -> core] vmp1 region: %X - %X\n", meme.vmp1.start, meme.vmp1.size);

	// This block scans for the end of the function just before the main sub we are looking for.
	// Instructions scanned for are:
	//     movzx   eax, byte ptr [ebp-1]
	//     imul    eax, 0x0CCCCCCCC
	//     pop     edi
	// Sig: 0F B6 45 FF 69 C0 CC CC CC CC 5F
	auto hasher_func = mem_scanner::scan_pattern("\x0F\xB6\x45\xFF\x69\xC0\xCC\xCC\xCC\xCC\x5F", "xxxxxxxxxxx", std::pair<int32_t, int32_t>(this->text.start, this->text.start + text.size))[0];
	if (!hasher_func)
	{
		mem_utils::dbgprintf("[debug -> core] couldn't grab hasher function\n");
		return;
	}

	// If found scan for the entry of the next function.
	// Instructions scanned for are:
	//     push ebp
	//     mov ebp, esp
	// All functions are aligned to 16 byte boundaries allowing this to work well.
	bool found_hasher_func = false;
	hasher_func += 16 - (hasher_func % 16); // Align to 16 byte boundary

	for (std::size_t i = 0; i < 2; i++)
	{
		if (*reinterpret_cast<std::uint8_t*>(hasher_func) == 0x55
			|| *reinterpret_cast<std::uint8_t*>(hasher_func + 1) == 0x8B
			|| *reinterpret_cast<std::uint8_t*>(hasher_func + 2) == 0xEC)
		{
			found_hasher_func = true;
			break;
		}

		hasher_func += 16;
	}

	// The region list contains a list the start addresses for every block to be scanned
	const auto region_list = scan_for_regions(this, std::pair<std::uintptr_t, std::uintptr_t>(this->vmp0.start, this->vmp0.start + this->vmp0.size), hasher_func);
	if (!region_list)
		scan_for_regions(this, std::pair<std::uintptr_t, std::uintptr_t>(this->text.start, this->text.start + this->text.size), hasher_func);

	if (!region_list)
	{
		mem_utils::dbgprintf("[debug -> core] failed to find region list.\n");
		return;
	}

	// The region sizes contains a list of sizes for each block to be scanned
	const auto region_sizes = scan_for_region_sizes(this, std::pair<std::uintptr_t, std::uintptr_t>(this->vmp0.start, this->vmp0.start + this->vmp0.size), hasher_func, region_list);
	if (!region_sizes)
		scan_for_region_sizes(this, std::pair<std::uintptr_t, std::uintptr_t>(this->text.start, this->text.start + this->text.size), hasher_func, region_list);

	if (!region_sizes)
	{
		mem_utils::dbgprintf("[debug -> core] failed to find region sizes.\n");
		return;
	}

	// Scan for the location of the core hasher that is hooked,
	//   which is entry to the main loop.
	// Instructions scanned for are:
	//     mov     eax, [ebx]
	//     add     eax, ebx
	//     imul    eax, 0x1594FE2D
	//     add     eax, edi
	//     rol     eax, 0x13
	// Sig: 8B 03 03 C3 69 C0 2D FE 94 15 03 C7 C1 C0 13
	core_hasher_start = mem_scanner::scan_pattern("\x8B\x03\x03\xC3\x69\xC0\x2D\xFE\x94\x15\x03\xC7\xC1\xC0\x13", "xxxxxxxxxxxxxxx", { this->text.start, this->text.start + text.size })[0];
	core_hasher_end = (core_hasher_start + 107); // End of main hasher, this never changes, if it does just scan for it

	mem_utils::dbgprintf("[debug -> core] Core hasher loop entry: %X\n", core_hasher_start);

	std::vector<std::uintptr_t> silent_checkers {}; // List of all found checkers, as of now should be 16

	// Scan for a possible start of a possible secondary hasher.
	// Instructions scanned for are:
	//     movsx  ecx, byte ptr [edx - 2]
	// Sig: 0F BE ?? FE
	for (auto& res : mem_scanner::scan_pattern("\x0F\xBE\x00\xFE", "xx?x", { this->text.start, this->text.start + this->text.size }))
	{
		bool possible = false;

		// If the first sig is found, scan for another section of the hasher.
		// This scan has 2 possible variants to search for.
		// Instructions scanned for are:
		//     Pattern 1:
		//         movsx  UNK, byte ptr [UNK - 2]
		//     Pattern 2:
		//         movsx  UNK, byte ptr [UNK - 0x11]
		// Sig 1: 0F BE ?? FE
		// Sig 2: 0F BE ?? EF
		if (mem_scanner::scan_pattern("\x0F\xBE\x00\xFF", "xx?x", { res, res + 50 }).size() == 1
			|| mem_scanner::scan_pattern("\x0F\xBE\x00\xEF", "xx?x", { res, res + 50 }).size() == 1)
			possible = true;

		if (possible)
		{
			// If both scans are successful thus far,
			//   scan for the entry of the hasher.
			// Byes scanned for are:
			//     push ebp
			//     mov ebp, esp
			// All functions are aligned to 16 byte boundaries allowing this to work well.
			auto entry = res - (res % 16); // Align to 16 byte boundary

			for (std::size_t i = 0; i < 5; i++)
			{
				if (*reinterpret_cast<std::uint8_t*>(entry) == 0x55
					|| *reinterpret_cast<std::uint8_t*>(entry + 1) == 0x8B
					|| *reinterpret_cast<std::uint8_t*>(entry + 2) == 0xEC)
				{
					// Finally scan for instructions that the hasher has to
					//   to help with collisions against random memory.
					// Instructions scanned for are (each must be found at at least once to continue):
					//     lea     UNK, [UNK + 2]
					//     mov     UNK, [ebp + 0xC]
					//     mov     UNK, [ebp + 8]
					// Sigs:
					//     8D ?? 02
					//     8B ?? 0C
					//     8B ?? 08
					// A special note is each one of these sigs has the potential
					//   to appear more than once in any given hasher.
					if (mem_scanner::scan_pattern("\x8D\x00\x02", "x?x", { entry, res }).size()
						&& mem_scanner::scan_pattern("\x8B\x00\x0C", "x?x", { entry, res }).size()
						&& mem_scanner::scan_pattern("\x8B\x00\x08", "x?x", { entry, res }).size())
					{
						silent_checkers.push_back(entry);
						mem_utils::dbgprintf("[debug -> core] %i secondary address: %X\n", silent_checkers.size(), mem_utils::rebase<uintptr_t>(entry));
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
		populated_hashes.reserve(16); // Reserve space to prevent regions from being copied for no reason

		// Because every hasher produces a slightly different result
		//   cache every hash for every checker before applying hooks.
		for (const auto silent_checker : silent_checkers)
		{
			active_hasher_t hasher{};
			hasher.entry = silent_checker;

			// As of now there are only 30 regions that are scanned.
			for (std::size_t i = 0; i < 30; i++)
			{
				const auto hash_start = hasher_func + decrypt_region_result(region_list[i]);
				const auto hash_size = decrypt_region_result(region_sizes[i]);

				const auto hash_t = reinterpret_cast<std::size_t(__cdecl*)(std::uintptr_t, std::uintptr_t, std::uintptr_t, std::uintptr_t)>(silent_checker);
				const auto hash = hash_t(hash_start, hash_size, 0, 0); // Call hash with a key of 0 to get a clean hash

				// Every checker has basic math operation with the passed key,
				//   simply brute force each one if not already determined.
				if (hash_size > 0 && hasher.enc == secondary_hash_encryption::unk_t)
					hasher.enc = bruteforce_encryption(silent_checker, hash, hash_start, hash_size);

				//mem_utils::dbgprintf("[debug -> core] hash start: %X\n", hash_start);
				hasher.hashes[hash_start] = hash;
			}

			// If the math operation has not been determined, the bypass will not work
			if (hasher.enc == secondary_hash_encryption::unk_t)
			{
				mem_utils::dbgprintf("[debug -> core] failed to grab hash type");
				return;
			}

			populated_hashes.push_back(hasher);
		}
	}

	// For a safe hook that will be 100% reliable without
	//   crashes or init detections, hook a job to be
	//   on the task scheduler and apply the hook on there.
	const auto job = this->get_job_by_name("US14116_pt2");
	std::memcpy(new_vftable, *reinterpret_cast<void**>(job), sizeof(std::uintptr_t) * 6);

	old_vftable = *reinterpret_cast<std::uintptr_t**>(job);
	new_vftable[5] = reinterpret_cast<std::uintptr_t>(job_hook);

	*reinterpret_cast<std::uintptr_t**>(job) = new_vftable;
	job_cache = job;
}