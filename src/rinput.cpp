#include "framework.h"
#include "shared.h"
#include "structs.h"
#include "safetyhook.hpp"
#include "MemoryMgr.h"
#include "rinput.h"
#include <hidusage.h>

#include "Hooking.Patterns.h"
#include <game.h>

uintptr_t Sys_QueEvent_addr;

import game;

namespace rinput {
	cevar_s* raw_input;
	int rawinput_x_current = 0;
	int rawinput_y_current = 0;
	int rawinput_x_old = 0;
	int rawinput_y_old = 0;

	uint32_t* window_center_x = 0;
	uint32_t* window_center_y = 0;

	void Sys_QueEvent(int type, int value, int value2, int ptrLength, void* ptr) {
		if (type == 1) {
			int time = *reinterpret_cast<int*>(exe(0x47BE20C,0x0489BC2C));
			__asm mov eax, time
		}
		else {
			__asm xor eax, eax
		}
		cdecl_call<void>(Sys_QueEvent_addr, type, value, value2, ptrLength, ptr);
	}

	static uintptr_t in_mouseold;
	static void rawInput_move()
	{
		if (raw_input && raw_input->base->integer) {
			auto delta_x = rawinput_x_current - rawinput_x_old;
			auto delta_y = rawinput_y_current - rawinput_y_old;

			rawinput_x_old = rawinput_x_current;
			rawinput_y_old = rawinput_y_current;

			SetCursorPos(*window_center_x, *window_center_y);
			Sys_QueEvent(3, delta_x, delta_y, 0, NULL);
		}
		else {
			rawinput_x_current = 0;
			rawinput_y_current = 0;
			rawinput_x_old = 0;
			rawinput_y_old = 0;

			cdecl_call<void>(in_mouseold);
		}
	}



	static void WM_INPUT_process(LPARAM lParam)
	{

		////

		UINT dwSize = sizeof(RAWINPUT);
		static RAWINPUT raw;
		GetRawInputData(reinterpret_cast<HRAWINPUT>(lParam), RID_INPUT, &raw, &dwSize, sizeof(RAWINPUTHEADER));
		if (raw_input && raw_input->base->integer) {
			rawinput_x_current += raw.data.mouse.lLastX;
			rawinput_y_current += raw.data.mouse.lLastY;
		}
	}

	static void rawInput_init(HWND hWnd)
	{
		RAWINPUTDEVICE rid[1];
		rid[0].usUsagePage = HID_USAGE_PAGE_GENERIC;
		rid[0].usUsage = HID_USAGE_GENERIC_MOUSE;
		rid[0].dwFlags = 0;
		rid[0].hwndTarget = hWnd;
		if (!RegisterRawInputDevices(rid, ARRAYSIZE(rid), sizeof(rid[0])))
			throw std::runtime_error("RegisterRawInputDevices failed");
	}

	uintptr_t MainWndProc_addr;
	LRESULT CALLBACK stub_MainWndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
	{

		switch (uMsg)
		{
		case WM_INPUT:
			WM_INPUT_process(lParam);
			return true;

		case WM_XBUTTONDOWN:
		case WM_XBUTTONUP:
		{
			int key;
			if (HIWORD(wParam) == XBUTTON1) {
				key = 203;
			}
			else if (HIWORD(wParam) == XBUTTON2) {
				key = 204;
			}
			else {
				break;
			}
			Sys_QueEvent(1, key, uMsg == WM_XBUTTONDOWN ? 1 : 0, 0, NULL);
			return true;
		}

		case WM_CREATE:
			//SetWindowLong(hWnd, GWL_STYLE, GetWindowLong(hWnd, GWL_STYLE) | WS_MINIMIZEBOX | WS_MAXIMIZEBOX);
			rawInput_init(hWnd);
			break;
		}

		return stdcall_call<LRESULT>(MainWndProc_addr,hWnd, uMsg, wParam, lParam);

	}
	void Init() {
		Memory::VP::ReadCall(exe(0x45294A,0x469C6A), Sys_QueEvent_addr);
		Memory::VP::InterceptCall(exe(0x452B99,0x469EB9), in_mouseold,rawInput_move);

		printf("MainWndProc_addr %p stub_MainWndProc %p\n", &MainWndProc_addr, stub_MainWndProc);
		Memory::VP::Read(exe(0x454992 + 1, 0x46BF01 + 1), MainWndProc_addr);
		Memory::VP::Patch<void*>(exe(0x454992 + 1, 0x46BF01 + 1), stub_MainWndProc);

		auto pattern = hook::pattern("8B 15 ? ? ? ? 51 52 FF 15 ? ? ? ? 8B 0D ? ? ? ? ? ? ? 8B 15");
		if (!pattern.empty()) {
			window_center_x = *(uint32_t**)pattern.get_first(2);
			window_center_y = *(uint32_t**)pattern.get_first(-4);

		}
		 pattern = hook::pattern("A1 ? ? ? ? 85 C0 74 ? A1 ? ? ? ? 85 C0 74 ? C7 05 ? ? ? ? 00 00 00 00 E9 ? ? ? ? E8");

		if (!pattern.empty()) {
			static auto clear_rawinput = safetyhook::create_mid(pattern.get_first(), [](SafetyHookContext& ctx) {
				rawinput_x_current = 0;
				rawinput_y_current = 0;
				rawinput_x_old = 0;
				rawinput_y_old = 0;
				});
		}

	}
}