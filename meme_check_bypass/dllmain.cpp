// dllmain.cpp : Defines the entry point for the DLL application.
#include <Windows.h>
#include <thread>

#include "integrity_check/integrity_check.hpp"

memcheck_t meme;

void main_instance()
{
	try
	{
		mem_utils::console();
		meme.initialize_bypass();
	}
	catch (std::exception& e)
	{
		printf("[Error] %s\n", e.what());
	}
}

bool __stdcall DllMain( HINSTANCE instance, std::int32_t call_reason, void* )
{
	if (call_reason == DLL_PROCESS_ATTACH)
		std::thread{ main_instance }.detach();

	return true;
}

