/*
			 AGIN-Engine Anti-Virus


			 Sebastian Rautenbach
			 ~~~~~~~~~~~~~~~~~~~~~


			 Apache License 2.0
			 ~~~~~~~~~~~~~~~~~~

			 All source and Images: Copyright 2023

			 Redistribution and use in source and binary forms, with or without
			 modification, are permitted provided that the following conditions
			 are met:

			 1. Redistributions or derivations of source code must retain the above
			 copyright notice, this list of conditions and the following disclaimer.

			 2. Redistributions or derivative works in binary form must reproduce
			 the above copyright notice. This list of conditions and the following
			 disclaimer must be reproduced in the documentation and/or other
			 materials provided with the distribution.

			 3. Neither the name of the copyright holder nor the names of its
			 contributors may be used to endorse or promote products derived
			 from this software without specific prior written permission.

			 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
			 "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
			 LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
			 A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
			 HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
			 SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
			 LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
			 DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
			 THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
			 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
			 OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/










#pragma once

#include <yara.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <filesystem>
#include <string>
#include <windows.h>
#include <boost/filesystem.hpp>
#include <Psapi.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "files_algorithm.h"

#define AV_OPERABLE 0
#define AV_INOPERABLE 1
#define SCAN_DESKTOP 0x01
#define SCAN_DOCUMENTS 0x02
#define SCAN_PROGRAMFILES 0x03
#define SCAN_STARTUP 0x04
#define SCAN_MEM 0x05




/*

	This class is almost like a container for all rules with their respective compiler

	This optimizes and avoids crashes because of to many rules loaded into a single instance compiler
*/

class yr_simpl_s {
public:
	yr_simpl_s() 
		: compiler(nullptr), rules(nullptr)
	{
		
	}

	~yr_simpl_s() {
	}

	/*
		Add rules to compiler
	*/

	void add_rules(size_t &AV_STATUS) noexcept {
		yr_compiler_get_rules(compiler, &rules);
		if (rules->arena == nullptr)
		{
			AV_STATUS = AV_INOPERABLE;
		}
	}

	/*
		Remove all rules
	*/

	void deconstruct_reg(size_t& AV_STATUS) {
		if(rules && AV_STATUS != AV_INOPERABLE)
			yr_rules_destroy(rules);
	}

	std::vector<std::string> files;
	YR_COMPILER* compiler = nullptr;
	YR_RULES* rules = nullptr;
};


class yara_scanner {
public:
	yara_scanner() {
		if (yr_initialize() != ERROR_SUCCESS)
			AV_STATUS = AV_INOPERABLE;
	}

	bool isRecentFile(std::string time) {
		
		size_t crnt_year;
		
		if (time.find("2023"))
		{
			if (time.find("Sep"))
				return true;
		}
		return false;
	}
	
	// check if file has been accessed recently
	bool isPotentialFile(const char* file_path)
	{
		struct stat fileStats;
		
		if (stat(file_path, &fileStats) == 0) {
			
			char timeBuffer[26];
			ctime_s(timeBuffer, sizeof(timeBuffer), &fileStats.st_atime);
			if (isRecentFile(timeBuffer))
				return true;

			ctime_s(timeBuffer, sizeof(timeBuffer), &fileStats.st_mtime);
			if (isRecentFile(timeBuffer))
				return true;

			ctime_s(timeBuffer, sizeof(timeBuffer), &fileStats.st_ctime);
			if (isRecentFile(timeBuffer))
				return true;
		}
		return false;
	}

	//Just for checks
	bool file_contain_badactor(const char* file_path) {
		FILE* open_file;
		fopen_s(&open_file, file_path, "r");

		if (open_file) {
			fseek(open_file, 0, SEEK_END);
			long file_size = ftell(open_file);
			fseek(open_file, 0, SEEK_SET);

			if (file_size > 0) {
				std::string file_contents;
				file_contents.resize(file_size);

				fread(&file_contents[0], 1, file_size, open_file);

				fclose(open_file); 
				std::string temp_path_check = file_path;
				if (file_contents.find("linux") != -1 || 
					temp_path_check.find("ELF") != -1 || 
					file_contents.find("elf") != -1   || 
					file_contents.find("mail") != -1  || 
					file_contents.find("Mozilla") != -1||
					file_contents.find("memory") != -1
					)
					return true;

				
			}
			else {
				return false;
			}
		}
		else {
			return false;
		}


		return false;

	}
	

	// generic functions
	void compile_rules(const char* file_path) {
		
		int crnt_yss_id = 0;
		char last_namespace_c = '~';
		int ittr_rules_max = 0;
		
		// get first character of the filename
		for (const auto& file : std::filesystem::directory_iterator(file_path)) {
			last_namespace_c = file.path().filename().c_str()[0];
			break;
		}
		

		yss_id_arr.push_back(new yr_simpl_s);
		yr_compiler_create(&yss_id_arr[0]->compiler);
		
		 // go through each file and add its rules to the compiler to be transformed into binary
		for (const auto& file : std::filesystem::directory_iterator(file_path))
		{
			
			if (file.is_regular_file())
			{

				// I am personally not quite sure how this works if its better to do it by name-spaces 
				// or to limit it by 5 files but for now solution 2 will be appropriate
				// so for performance we add rules to a new compiler for every 5 rules

				if ( ittr_rules_max > max_rules_comp)
				{
					//create new compiler with a new set of rules

					++crnt_yss_id;
					yss_id_arr.push_back(new yr_simpl_s);
					yr_compiler_create(&yss_id_arr[crnt_yss_id]->compiler);
					yss_id_arr[crnt_yss_id]->files.push_back(file.path().string().c_str());
					ittr_rules_max = 0;
				}

				// add all rule files with the same namespace to the compiler
				FILE* open_file;
				fopen_s(&open_file, file.path().string().c_str(), "r");

				
				if (!file_contain_badactor(file.path().string().c_str()))
				{
					if (yr_compiler_add_file(yss_id_arr[crnt_yss_id]->compiler, open_file, nullptr, std::to_string(ittr_rules_max).c_str()) != ERROR_SUCCESS)
					{
						AV_STATUS = AV_INOPERABLE; 
						return;
					}
				}
				

				if (open_file != nullptr)
					fclose(open_file);

				++ittr_rules_max;
			}
		}

	}
	/*
		Add rules to it's respective compiler
	*/
	void add_to_rules() {
		for (int i = 0; i < yss_id_arr.size() - 1; i++)
		{
			yss_id_arr[i]->add_rules(AV_STATUS);
		}
	}

	/*
	
		Check if the directory is allowed to access,
		if the function catches an exception it means
		that the file doesn't exist or doesn't contain valid
		permission 
	*/
	
	bool isFileReadable(const boost::filesystem::directory_entry& e) {
		boost::filesystem::file_status status = boost::filesystem::status(e);
		
		try {
			for (const auto& file : boost::filesystem::directory_iterator(e)) {
				return true;
			}
			return true;
		}
		catch (const std::exception& e) {
			return false;
		}
		return false;
	}

	void scan_files(const char* file_path, std::vector<bool> &scanning) noexcept {
		
		// create a temp bool variable just to parse it through for no problems
		std::vector<bool> temp_bool;
		temp_bool.emplace_back(false);

		for (const auto& file : boost::filesystem::directory_iterator(file_path))
		{
			// check if the anti virus is still running
			if(AV_STATUS == AV_INOPERABLE)
				break;
			
			
			
				
		
			if (boost::filesystem::is_directory(file.status())) {
				// If it's a folder then we'll have to do a recursion
				if (isFileReadable(file))
					scan_files(file.path().string().c_str(), temp_bool);
			}
			else if (boost::filesystem::is_regular_file(file.status()) && isPotentialFile(file.path().string().c_str()))
			{
				crnt_scanning_path = "";
				crnt_scanning_path += file.path().string();
				boost::uintmax_t fileSize = 0;
				

				/*
				
					Ensure that it does not scan a file bigger than a 100mb for performance reasons
					
				*/
				
				try {
					fileSize = boost::filesystem::file_size(file.path().string().c_str()) / 1000000;
				}catch (const boost::filesystem::filesystem_error& e) {

				}





				if(fileSize < 100)
				{




					//scan the file by going through every rule
					for (int i = 0; i < yss_id_arr.size() - 1; i++)
					{
						YR_SCANNER* scanner;

						yr_scanner_create(yss_id_arr[i]->rules, &scanner);

						if (yr_rules_scan_file(yss_id_arr[i]->rules, file.path().string().c_str(), SCAN_FLAGS_FAST_MODE, callbackexternvar, nullptr, 0) == ERROR_SUCCESS)
						{
							contaminated_files.push_back(file.path().string());
							break;
						}

						yr_scanner_destroy(scanner);
					}





				}
			}
			
			
		}

		// we return that the scanning for this directory is finished

		if(!scanning.empty())
			scanning.erase(scanning.begin());
	}


	// Remove all rules from arr
	void deconstruct_instance() {
		for (int i = yss_id_arr.size() - 1; i > 0; i--)
		{
			yss_id_arr[i]->deconstruct_reg(AV_STATUS);
			yss_id_arr.pop_back();
		}
		yr_finalize();
	}
	
	// create a list of all currently running process IDs 
	std::vector<DWORD> get_running_PIds() {
		
		std::vector<DWORD> all_PIds;
		
	
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (snapshot == INVALID_HANDLE_VALUE) {
			std::cout << "Failed to create process snapshot./n";
			return all_PIds;
		}
		DWORD currentThreadId = GetCurrentProcessId();


		PROCESSENTRY32 processInfo;
		processInfo.dwSize = sizeof(PROCESSENTRY32);
		
		// get snapshot of the first processes
		if (!Process32First(snapshot, &processInfo)) {
			std::cerr << "Failed to retrieve process information." << std::endl;
			CloseHandle(snapshot);
			return all_PIds;
		}

		// loop though all captured processes 
		do {
			if (processInfo.th32ProcessID == currentThreadId) {
				continue;
			}
			all_PIds.push_back(processInfo.th32ProcessID);
		} while (Process32Next(snapshot, &processInfo) && processInfo.szExeFile != L"wizm.exe");




		CloseHandle(snapshot);

		return all_PIds;

	}

	/*
	
	
				get the starting address of a process
	
	
	*/
	DWORD get_starting_address(DWORD PID) {
		HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, PID);
		
		if (processHandle == nullptr) {
			/*std::cerr << "Failed to open process. Error code: " << GetLastError() << std::endl;*/
			return -1;
		}
	
		HMODULE moduleHandles[1024];
		DWORD moduleSize;
	

		if (EnumProcessModules(processHandle, moduleHandles, sizeof(moduleHandles), &moduleSize)) {
		
			if (moduleSize > 0) {
				MODULEINFO moduleInfo;

				if (GetModuleInformation(processHandle, moduleHandles[0], &moduleInfo, sizeof(moduleInfo))) {
				
					return reinterpret_cast<uintptr_t>(moduleInfo.lpBaseOfDll);
				
				}
			}
		
		}
		
		return -1;
	
	}
	/*
	
	
				scan process in memory for any malicious content
	
	
	*/						// Call back function
	void scan_crnt_mem_files(std::vector<bool>& scanning) {
		
		
		std::cout << "SCANNING MEM:/n";
		
		for (const auto& PID : get_running_PIds())
		{
			SIZE_T bytesRead = 0;
			size_t bufferSize = 4096;
			BYTE* buffer = new BYTE[bufferSize];

			// get current base address for process
			DWORD startAddress = get_starting_address(PID);

			HANDLE process_handle = OpenProcess(PROCESS_VM_READ, FALSE, PID);
			if (process_handle == nullptr) {

			//	std::cout << "mem file not accessible:" << PID << "/n";
				// stop if the ID doesn't exist
			}
			else
			{
				if (ReadProcessMemory(process_handle, (LPCVOID)startAddress, buffer, bufferSize, &bytesRead)) {
					
					// doing a callback function to the GUI to ensure that things are happenen
					std::string compiled_return = "mem file accessible:";
					compiled_return += std::to_string(PID);
					
					
					for (int i = 0; i < yss_id_arr.size() - 1; i++)
					{
						//scan the buffer the AV got from the active process
						YR_SCANNER* scanner;
						yr_scanner_create(yss_id_arr[i]->rules, &scanner);
						
						if (yr_rules_scan_mem(yss_id_arr[i]->rules, buffer, bytesRead, SCAN_FLAGS_PROCESS_MEMORY, callbackexternvar, nullptr, 0) == ERROR_SUCCESS)
						{
							// add PID file path to contaminated_files

							// open the process to retrieve the file location

							HANDLE filepath_handle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, PID);
							if (!filepath_handle)
								break;  // return to normal loop if process can't open


							/*
							
							
										create the filepath and the maximum path size,
										this is just something to keep in mind that it is
										converting to a normal string which can cause issues
										down the road because of the conversation

							
							*/ 
							DWORD size = MAX_PATH;
							wchar_t filePath[MAX_PATH];

							std::wstring wfile_path;
							QueryFullProcessImageName(filepath_handle, 0, filePath, &size);
							wfile_path = filePath;
							CloseHandle(filepath_handle);

							contaminated_files.push_back(std::string(wfile_path.begin(), wfile_path.end()));
						}

						yr_scanner_destroy(scanner);
						
					}




				}


				else {
					// Failed to read memory
				}

				CloseHandle(process_handle);


			}
		}

		if (!scanning.empty())
			scanning.erase(scanning.begin());
	}

	// set status of anti virus in case it's not usable

	void set_av_status(size_t status) {
		AV_STATUS = status;
	}



private:
	YR_SCANNER* scanner;

	// Amount of rules that will be fit inside an instance
	size_t max_rules_comp = 10;

	// If the AV_STATUS is not operable it indicates that something went wrong and needs 
	// a restart
	size_t AV_STATUS = AV_OPERABLE;
	
	std::vector<yr_simpl_s*> yss_id_arr;



public:

	// call back function

	YR_CALLBACK_FUNC callbackexternvar;

	// just for UI updates

	std::string crnt_scanning_path;

	// this needs to be changed in the future to accept w_char types

	std::vector<std::string> contaminated_files;


};
