#include "pin.H"

#include <assert.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

#include "Tracer.h"

#include <fstream>
#include <string>
#include <set>
#include <map>
#include <iostream>
#include <algorithm>

#include <iomanip>
#include <stdlib.h>
#include <stdio.h>
#include <malloc.h>
#include <errno.h>
#include <values.h>
extern "C" {
#include "xed-interface.h"
}

#pragma pack(1)

namespace common {
	const unsigned int TEN = 10;
	typedef ADDRINT top_ten_t;
	top_ten_t g_top_ten[TEN];
	ADDRINT g_main_addr;
}

namespace ex2 {

	typedef const std::pair<ADDRINT, USIZE> bbl_key_t;	// bbl_addr, bbl_size
	struct bbl_val_t
	{
		unsigned long counter;	// #times this BBL was executed
		/* const */ bool ends_with_direct_jump;
		/* const */ std::string rtn_name;
		/* const */ ADDRINT rtn_addr;
		/* const */ USIZE size;

		/* const */ std::string img_name;
		/* const */ ADDRINT img_addr;

		ADDRINT target[2]; // taken/not taken
		std::map<bbl_key_t, int> target_count;	// could have more than 2 targets (different BBs on same address)
		int idx_for_printing;	// used only for printing
	};

	std::pair<bbl_key_t, bbl_val_t>* g_last_bbl_ptr = NULL;

	typedef std::map<bbl_key_t, bbl_val_t> g_bbl_map_t;
	g_bbl_map_t g_bbl_map;

	typedef std::map<std::string, ADDRINT> g_img_map_t;
	g_img_map_t g_img_map;

	VOID bbl_count(std::pair<bbl_key_t, bbl_val_t>* curr_bbl_ptr)
	{
		if(curr_bbl_ptr == NULL) {
			goto out;
		}
		curr_bbl_ptr->second.counter++;
		if (!g_last_bbl_ptr)
			goto out;
		if(curr_bbl_ptr->second.rtn_addr != g_last_bbl_ptr->second.rtn_addr)
			goto out;
		if ((g_last_bbl_ptr->second.target[1] == curr_bbl_ptr->first.first)  //fall through
		 || (g_last_bbl_ptr->second.ends_with_direct_jump    // direct branch target
			 && g_last_bbl_ptr->second.target[0] == curr_bbl_ptr->first.first)) {	// direct branch target
			g_last_bbl_ptr->second.target_count[curr_bbl_ptr->first]++;
		}
	out:
		g_last_bbl_ptr = curr_bbl_ptr;

	}

	VOID Img(IMG img, VOID *v)
	{
		if (IMG_IsMainExecutable(img))
			common::g_main_addr = IMG_LowAddress(img);

		g_img_map[IMG_Name(img)] = IMG_LowAddress(img);
	}

	struct count_to_file_t
	{
		unsigned int count;
		ADDRINT addr;
		USIZE size;
	};
	const unsigned int MAX_EDGES = 5;

	struct bbl_to_file_t
	{
		unsigned long counter;
		ADDRINT first_ins;
		ADDRINT rtn_addr;
		UINT32 size;
		char img_name[255];
		ADDRINT target[2];
		count_to_file_t target_count[MAX_EDGES];
	};

	void update_file(const std::string &file_name)
	{
		int fd;
		char *buff, *p;
		unsigned int count = 0, map_size = 0;

		if ((fd = open(file_name.c_str(), O_RDONLY)) >= 0) { //read file

			map_size = sizeof(count);
			if ((p = buff = (char*)mmap(0, map_size, PROT_READ, MAP_SHARED, fd, 0)) == (caddr_t) -1) {std::cerr << "Error" << std::endl; return;}

			count = *(unsigned int*)p;
			map_size += count * sizeof(bbl_to_file_t);

			if ((p = buff = (char*)mmap(0, map_size, PROT_READ, MAP_SHARED, fd, 0)) == (caddr_t) -1) {std::cerr << "Error" << std::endl; return;}
			p += sizeof(count);

			for (unsigned int i = 0; i < count; ++i) {
				bbl_to_file_t *bbl = (bbl_to_file_t*)p;
				p += sizeof (*bbl);

				ADDRINT img_addr = g_img_map[bbl->img_name];

				bbl_val_t &bbl_val = g_bbl_map[std::make_pair(bbl->first_ins + img_addr, bbl->size)];

				bbl_val.counter += bbl->counter;
				bbl_val.rtn_addr = bbl->rtn_addr + img_addr;
				bbl_val.img_name = std::string(bbl->img_name);
				bbl_val.img_addr = img_addr;
				bbl_val.target[0] = bbl->target[0] + img_addr;
				bbl_val.target[1] = bbl->target[1] + img_addr;

				for (unsigned int j = 0; j < MAX_EDGES; ++j) {
					ADDRINT bbl_addr = bbl->target_count[j].addr;
					USIZE bbl_size = bbl->target_count[j].size;
					unsigned int count = bbl->target_count[j].count;

					if (count)
						bbl_val.target_count[make_pair(bbl_addr, bbl_size)] += count;
				}

				RTN rtn = RTN_FindByAddress(bbl_val.rtn_addr);
				if (RTN_Valid(rtn)) bbl_val.rtn_name = std::string(RTN_Name(rtn));
			}

			if (close(fd) < 0) {std::cerr << "Error" << std::endl; return;}
		}

		if ((fd = open(file_name.c_str(), O_RDWR | O_CREAT , S_IRWXU)) < 0) {std::cerr << "Error" << std::endl; return;}

		count = g_bbl_map.size();
		map_size = sizeof(count) + count * sizeof(bbl_to_file_t);

		//write dummy byte
		if (lseek(fd, map_size-1, 0) == -1) {std::cerr << "Error" << std::endl; return;}
		if (write(fd, "", 1) != 1) {std::cerr << "Error" << std::endl; return;}
		if (lseek(fd, 0, 0) == -1) {std::cerr << "Error" << std::endl; return;}

		if ((p = buff = (char*)mmap(0, map_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0)) == (caddr_t) -1) {
			std::cerr << "Error" << std::endl;
			return;
		}

		*(unsigned int*)p = count;
		p += sizeof(count);

		for (g_bbl_map_t::const_iterator i = g_bbl_map.begin(); i != g_bbl_map.end(); ++i)
		{
			bbl_to_file_t *bbl = (bbl_to_file_t*)p;
			p += sizeof (*bbl);

			bbl->first_ins = i->first.first - i->second.img_addr;
			bbl->size = i->first.second;

			bbl->counter = i->second.counter;
			bbl->rtn_addr = i->second.rtn_addr - i->second.img_addr;
			strcpy(bbl->img_name, i->second.img_name.c_str());
			bbl->target[0] = i->second.target[0] - i->second.img_addr;
			bbl->target[1] = i->second.target[1] - i->second.img_addr;

			unsigned int n = 0;
			for (std::map<bbl_key_t, int>::const_iterator j = i->second.target_count.begin();
					j != i->second.target_count.end() && n < MAX_EDGES;
					++j, ++n) {
				bbl->target_count[n].addr  = j->first.first;
				bbl->target_count[n].size  = j->first.second;
				bbl->target_count[n].count = j->second;
			}

			for (;n < MAX_EDGES; ++n)
			{
				bbl->target_count[n].addr  =
				bbl->target_count[n].size  =
				bbl->target_count[n].count = 0;
			}
		}

		if (close(fd) < 0) {std::cerr << "Error" << std::endl; return;}
	}

	VOID Trace(TRACE trace, VOID *v)
	{
		for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
		{
			INS first_ins = BBL_InsHead(bbl);
			INS last_ins = BBL_InsTail(bbl);

			ADDRINT bbl_addr = BBL_Address(bbl);
			USIZE bbl_size = BBL_Size(bbl) - INS_Size(last_ins);
			bbl_key_t bbl_key = make_pair(bbl_addr, bbl_size);

			RTN rtn = INS_Rtn(first_ins);
			if (!RTN_Valid(rtn)) {
				BBL_InsertCall(bbl,
				IPOINT_BEFORE,
				(AFUNPTR)bbl_count,
				IARG_PTR, (void*)NULL,
				IARG_END);
				continue;
			}

			IMG img = IMG_FindByAddress(bbl_addr);

			g_bbl_map_t::iterator it = g_bbl_map.find(bbl_key);
			if(it == g_bbl_map.end()) {	// creating a new entry in the map
				struct bbl_val_t bbl_val;

				bbl_val.counter = 0;
				bbl_val.ends_with_direct_jump = INS_IsDirectBranch(last_ins);
				bbl_val.rtn_name = RTN_Name(rtn);
				bbl_val.rtn_addr = RTN_Address(rtn);
				bbl_val.img_name = IMG_Name(img);
				bbl_val.img_addr = IMG_LowAddress(img);
				bbl_val.target[0] = bbl_val.target[1] = 0;
				if(INS_IsDirectBranchOrCall(last_ins))
					bbl_val.target[0] = INS_DirectBranchOrCallTargetAddress(last_ins);

				if (INS_HasFallThrough(last_ins))
					bbl_val.target[1] = INS_NextAddress(last_ins);

				it = g_bbl_map.insert(g_bbl_map.begin(), make_pair(bbl_key, bbl_val));
			}

			std::pair<bbl_key_t, bbl_val_t>* bbl_ptr = &(*it);

			BBL_InsertCall(bbl,
				IPOINT_BEFORE,
				(AFUNPTR)bbl_count,
				IARG_PTR, (void*)bbl_ptr,
				IARG_END);

			//std::cout << std::hex << bbl_val_ptr->first_ins << std::dec << ": " << bbl_val_ptr->size << std::endl;
			//std::cout << std::hex << INS_Address(first_ins) << std::dec << ": " << INS_Disassemble(first_ins) << std::endl;
			//std::cout << std::hex << INS_Address(last_ins) << std::dec << ": " << INS_Disassemble(last_ins) << std::endl;

		}
	}

	struct printing_rtn_t {
		unsigned long counter;	//counter*bbl_size
		string rtn_name;
		ADDRINT rtn_addr;
		ADDRINT img_addr;
		std::set<std::pair<ADDRINT, USIZE> > bbls;	// I will use the order as index. <base, size> is good for sorting
													//  I want it to be bbl_key_t, but it is const for compilation of
													// other stuff. BAH
	};

	struct cmp_printing_rtn{
		bool operator()(const printing_rtn_t& n1, const printing_rtn_t& n2) const {
			if (n1.counter > n2.counter)
				return true;
			if (n1.counter < n2.counter)
				return false;

			if (n1.rtn_name > n2.rtn_name)
				return true;
			if (n1.rtn_name < n2.rtn_name)
				return false;
			return (n1.rtn_addr > n2.rtn_addr);
		}
	};
	
	void print(const std::string &file_name)
	{
		std::ofstream file(file_name.c_str());

		std::map<ADDRINT, printing_rtn_t> printing_ds; // key is rtn_addr

		for(g_bbl_map_t::iterator it = g_bbl_map.begin() ; it != g_bbl_map.end() ; ++it) {
			std::map<ADDRINT, printing_rtn_t>::iterator print_it = printing_ds.find(it->first.first);
			if(print_it == printing_ds.end()) {
				printing_rtn_t printing_rtn;
				printing_rtn.counter = 0;
				printing_rtn.rtn_name = it->second.rtn_name;
				printing_rtn.rtn_addr = it->second.rtn_addr;
				printing_rtn.img_addr = it->second.img_addr;
				print_it = printing_ds.insert(printing_ds.begin(), make_pair(it->second.rtn_addr, printing_rtn));
			}
			print_it->second.counter += (it->first.second * it->second.counter);
			print_it->second.bbls.insert(it->first);
		}

		std::set<printing_rtn_t, cmp_printing_rtn> printing_ds_sorted;
		for(std::map<ADDRINT, printing_rtn_t>::iterator print_it = printing_ds.begin() ; print_it != printing_ds.end() ; ++print_it) {
			printing_ds_sorted.insert(print_it->second);
		}

		unsigned int top_rtn_idx = 0;
		for(std::set<printing_rtn_t, cmp_printing_rtn>::iterator print_it = printing_ds_sorted.begin() ; print_it != printing_ds_sorted.end() ; ++print_it) {
			
			if ((top_rtn_idx < common::TEN) && (print_it->img_addr == common::g_main_addr))
				common::g_top_ten[top_rtn_idx++] = print_it->rtn_addr;
			
			file << (print_it->rtn_name) <<
				" at 0x" << std::hex << print_it->rtn_addr -  print_it->img_addr <<
				std::dec << " : icount: " << (print_it->counter) << std::endl;

			int i = 0;
			std::set<std::pair<unsigned long, std::pair<bbl_val_t*,bbl_val_t*> > > edges;
			for(std::set<std::pair<ADDRINT, USIZE> >::const_iterator bbl_it = print_it->bbls.begin() ; bbl_it != print_it->bbls.end() ; ++bbl_it) {
				bbl_key_t bbl_key = *bbl_it;
				bbl_val_t* bbl_val = &(g_bbl_map[bbl_key]);
				file << "\tBB" << i << std::hex <<
					": 0x"  << bbl_key.first - bbl_val->img_addr <<
					" - 0x" << bbl_key.first + bbl_key.second  - bbl_val->img_addr <<
					std::dec << std::endl;
					bbl_val->idx_for_printing = i;
					i++;
					for(std::map<bbl_key_t, int>::iterator edge_it = bbl_val->target_count.begin(); edge_it != bbl_val->target_count.end() ; ++edge_it) {
						edges.insert(make_pair(edge_it->second, make_pair(bbl_val, &(g_bbl_map[edge_it->first]))));
					}
			}
			i = 0;
			for(std::set<std::pair<unsigned long, std::pair<bbl_val_t*,bbl_val_t*> > >::reverse_iterator it = edges.rbegin() ; it != edges.rend() ; ++it) {
				file << "\t\tEdge" << i << ": BB" << it->second.first->idx_for_printing << " --> BB" << it->second.second->idx_for_printing << "\t" << it->first << std::endl;
				i++;
			}
		}

	}

	void write_top10(const std::string &file_name)
	{
		int fd;
		char *p;
		unsigned int count = 0, map_size = 0;

		if ((fd = open(file_name.c_str(), O_RDWR | O_CREAT , S_IRWXU)) >= 0) { //read file

			map_size = sizeof(count);
			if ((p = (char*)mmap(0, map_size, PROT_READ, MAP_SHARED, fd, 0)) == (caddr_t) -1) {std::cerr << "Error" << std::endl; return;}

			count = *(unsigned int*)p;
			map_size += count * sizeof(bbl_to_file_t) + sizeof(common::g_top_ten);

			//write dummy byte
			if (lseek(fd, map_size-1, 0) == -1) {std::cerr << "Error" << std::endl; return;}
			if (write(fd, "", 1) != 1) {std::cerr << "Error" << std::endl; return;}
			if (lseek(fd, 0, 0) == -1) {std::cerr << "Error" << std::endl; return;}

			if ((p = (char*)mmap(0, map_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0)) == (caddr_t) -1) {std::cerr << "Error" << std::endl; return;}
			p += sizeof(count) + count * sizeof(bbl_to_file_t);

			memcpy(p, common::g_top_ten, sizeof(common::g_top_ten));

			if (close(fd) < 0) {std::cerr << "Error" << std::endl; return;}
		}
			
	}
	
	VOID Fini(INT32 code, VOID *v)
	{
		update_file("__profile.map");
		print("rtn-output.txt");
		write_top10("__profile.map");
	}
}

namespace ex3 {
	BOOL KnobVerbose = FALSE;
	BOOL KnobDumpTranslatedCode = FALSE;
	BOOL KnobDoNotCommitTranslatedCode = FALSE;

	/* ===================================================================== */
	/* Global Variables */
	/* ===================================================================== */
	std::ofstream* g_out = 0;

	// For XED:
	#if defined(TARGET_IA32E)
		xed_state_t g_dstate = {XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b};
	#else
		xed_state_t g_dstate = { XED_MACHINE_MODE_LEGACY_32, XED_ADDRESS_WIDTH_32b};
	#endif

	//For XED: Pass in the proper length: 15 is the max. But if you do not want to
	//cross pages, you can pass less than 15 bytes, of course, the
	//instruction might not decode if not enough bytes are provided.
	const unsigned int g_max_inst_len = XED_MAX_INSTRUCTION_BYTES;

	ADDRINT g_lowest_sec_addr = 0;
	ADDRINT g_highest_sec_addr = 0;

	#define MAX_PROBE_JUMP_INSTR_BYTES  14

	// tc containing the new code:
	char *g_tc;
	int g_tc_cursor = 0;

	// instruction map with an entry for each new instruction:
	typedef struct {
		ADDRINT orig_ins_addr;
		ADDRINT new_ins_addr;
		ADDRINT orig_targ_addr;
		bool hasNewTargAddr;
		char encoded_ins[XED_MAX_INSTRUCTION_BYTES];
		xed_category_enum_t category_enum;
		unsigned int size;
		int new_targ_entry;
	} instr_map_t;

	instr_map_t *g_instr_map = NULL;
	int g_num_of_instr_map_entries = 0;
	int g_max_ins_count = 0;

	// total number of routines in the main executable module:
	int g_max_rtn_count = 0;

	// Tables of all candidate routines to be translated:
	typedef struct {
		ADDRINT rtn_addr;
		USIZE rtn_size;
		int instr_map_entry;   // negative instr_map_entry means routine does not have a translation.
		bool isSafeForReplacedProbe;
	} translated_rtn_t;

	translated_rtn_t *g_translated_rtn;
	int g_translated_rtn_num = 0;

	void read_top10(const std::string &file_name)
	{
		int fd;
		char *p;
		unsigned int count = 0, map_size = 0;

		if ((fd = open(file_name.c_str(), O_RDONLY)) >= 0) { //read file

			map_size = sizeof(count);
			if ((p = (char*)mmap(0, map_size, PROT_READ, MAP_SHARED, fd, 0)) == (caddr_t) -1) {std::cerr << "Error" << std::endl; return;}

			count = *(unsigned int*)p;
			map_size += count * sizeof(ex2::bbl_to_file_t) + sizeof(common::g_top_ten);

			if ((p = (char*)mmap(0, map_size, PROT_READ, MAP_SHARED, fd, 0)) == (caddr_t) -1) {std::cerr << "Error" << std::endl; return;}
			p += sizeof(count) + count * sizeof(ex2::bbl_to_file_t);

			memcpy(common::g_top_ten, p, sizeof(common::g_top_ten));

			if (close(fd) < 0) {std::cerr << "Error" << std::endl; return;}
		}
	}
	
#if 0
	/* ============================================================= */
	/* Service dump routines                                         */
	/* ============================================================= */

	/*************************/
	/* dump_all_image_instrs */
	/*************************/
	void dump_all_image_instrs(IMG img)
	{
		for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
		{
			for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
			{

				// Open the RTN.
				RTN_Open( rtn );

				cerr << RTN_Name(rtn) << ":" << endl;

				for( INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins) )
				{
					  cerr << "0x" << hex << INS_Address(ins) << ": " << INS_Disassemble(ins) << endl;
				}

				// Close the RTN.
				RTN_Close( rtn );
			}
		}
	}


	/*************************/
	/* dump_instr_from_xedd */
	/*************************/
	void dump_instr_from_xedd (xed_decoded_inst_t* xedd, ADDRINT address)
	{
		// debug print decoded instr:
		char disasm_buf[2048];

		xed_uint64_t runtime_address = reinterpret_cast<xed_uint64_t>(address);  // set the runtime adddress for disassembly

		xed_decoded_inst_dump_intel_format(xedd, disasm_buf, sizeof(disasm_buf), runtime_address);

		cerr << hex << address << ": " << disasm_buf <<  endl;
	}


	/************************/
	/* dump_instr_from_mem */
	/************************/
	void dump_instr_from_mem (ADDRINT *address, ADDRINT new_addr)
	{
	  char disasm_buf[2048];
	  xed_decoded_inst_t new_xedd;

	  xed_decoded_inst_zero_set_mode(&new_xedd,&g_dstate);

	  xed_error_enum_t xed_code = xed_decode(&new_xedd, reinterpret_cast<UINT8*>(address), g_max_inst_len);

	  BOOL xed_ok = (xed_code == XED_ERROR_NONE);
	  if (!xed_ok){
		  cerr << "invalid opcode" << endl;
		  return;
	  }

	  xed_decoded_inst_dump_intel_format(&new_xedd, disasm_buf, 2048, new_addr);

	  cerr << "0x" << hex << new_addr << ": " << disasm_buf <<  endl;

	}


	/****************************/
	/*  dump_entire_instr_map() */
	/****************************/
	void dump_entire_instr_map()
	{
		for (int i=0; i < g_num_of_instr_map_entries; i++) {
			for (int j=0; j < g_translated_rtn_num; j++) {
				if (g_translated_rtn[j].instr_map_entry == i) {

					RTN rtn = RTN_FindByAddress(g_translated_rtn[j].rtn_addr);

					if (rtn == RTN_Invalid()) {
						cerr << "Unknwon"  << ":" << endl;
					} else {
					  cerr << RTN_Name(rtn) << ":" << endl;
					}
				}
			}
			dump_instr_from_mem ((ADDRINT *)g_instr_map[i].new_ins_addr, g_instr_map[i].new_ins_addr);
		}
	}


	/**************************/
	/* dump_instr_map_entry */
	/**************************/
	void dump_instr_map_entry(int instr_map_entry)
	{
		cerr << dec << instr_map_entry << ": ";
		cerr << " orig_ins_addr: " << hex << g_instr_map[instr_map_entry].orig_ins_addr;
		cerr << " new_ins_addr: " << hex << g_instr_map[instr_map_entry].new_ins_addr;
		cerr << " orig_targ_addr: " << hex << g_instr_map[instr_map_entry].orig_targ_addr;

		ADDRINT new_targ_addr;
		if (g_instr_map[instr_map_entry].new_targ_entry >= 0)
			new_targ_addr = g_instr_map[g_instr_map[instr_map_entry].new_targ_entry].new_ins_addr;
		else
			new_targ_addr = g_instr_map[instr_map_entry].orig_targ_addr;

		cerr << " new_targ_addr: " << hex << new_targ_addr;
		cerr << "    new instr:";
		dump_instr_from_mem((ADDRINT *)g_instr_map[instr_map_entry].encoded_ins, g_instr_map[instr_map_entry].new_ins_addr);
	}

	/*************/
	/* dump_tc() */
	/*************/
	void dump_tc()
	{
	  char disasm_buf[2048];
	  xed_decoded_inst_t new_xedd;
	  ADDRINT address = (ADDRINT)&g_tc[0];
	  unsigned int size = 0;

	  while (address < (ADDRINT)&g_tc[g_tc_cursor]) {

		  address += size;

		  xed_decoded_inst_zero_set_mode(&new_xedd,&g_dstate);

		  xed_error_enum_t xed_code = xed_decode(&new_xedd, reinterpret_cast<UINT8*>(address), g_max_inst_len);

		  BOOL xed_ok = (xed_code == XED_ERROR_NONE);
		  if (!xed_ok){
			  cerr << "invalid opcode" << endl;
			  return;
		  }

		  xed_decoded_inst_dump_intel_format(&new_xedd, disasm_buf, 2048, address);

		  cerr << "0x" << hex << address << ": " << disasm_buf <<  endl;

		  size = xed_decoded_inst_get_length (&new_xedd);
	  }
	}
#endif

	/* ============================================================= */
	/* Translation routines                                         */
	/* ============================================================= */

	/*************************/
	/* add_new_instr_entry() */
	/*************************/
	int add_new_instr_entry(xed_decoded_inst_t *xedd, ADDRINT pc, unsigned int size)
	{
		// copy orig instr to instr map:
		ADDRINT orig_targ_addr = 0;

		if (xed_decoded_inst_get_length (xedd) != size) {
			cerr << "Invalid instruction decoding" << endl;
			return -1;
		}

		xed_uint_t disp_byts = xed_decoded_inst_get_branch_displacement_width(xedd);

		xed_int32_t disp;

		if (disp_byts > 0) { // there is a branch offset.
		  disp = xed_decoded_inst_get_branch_displacement(xedd);
		  orig_targ_addr = pc + xed_decoded_inst_get_length (xedd) + disp;
		}

		// Converts the decoder request to a valid encoder request:
		xed_encoder_request_init_from_decode (xedd);

		unsigned int new_size = 0;

		xed_error_enum_t xed_error = xed_encode (xedd, reinterpret_cast<UINT8*>(g_instr_map[g_num_of_instr_map_entries].encoded_ins), g_max_inst_len , &new_size);
		if (xed_error != XED_ERROR_NONE) {
			cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
			return -1;
		}

		// add a new entry in the instr_map:
		g_instr_map[g_num_of_instr_map_entries].orig_ins_addr = pc;
		g_instr_map[g_num_of_instr_map_entries].new_ins_addr = (ADDRINT)&g_tc[g_tc_cursor];  // set an initial estimated addr in tc
		g_instr_map[g_num_of_instr_map_entries].orig_targ_addr = orig_targ_addr;
		g_instr_map[g_num_of_instr_map_entries].hasNewTargAddr = false;
		g_instr_map[g_num_of_instr_map_entries].new_targ_entry = -1;
		g_instr_map[g_num_of_instr_map_entries].size = new_size;
		g_instr_map[g_num_of_instr_map_entries].category_enum = xed_decoded_inst_get_category(xedd);

		g_num_of_instr_map_entries++;

		// update expected size of tc:
		g_tc_cursor += new_size;

		if (g_num_of_instr_map_entries >= g_max_ins_count) {
			cerr << "out of memory for map_instr" << endl;
			return -1;
		}

#if 0
		// debug print new encoded instr:
		if (KnobVerbose) {
			cerr << "    new instr:";
			dump_instr_from_mem((ADDRINT *)g_instr_map[g_num_of_instr_map_entries-1].encoded_ins, g_instr_map[g_num_of_instr_map_entries-1].new_ins_addr);
		}
#endif

		return new_size;
	}

	/*************************************************/
	/* chain_all_direct_br_and_call_target_entries() */
	/*************************************************/
	int chain_all_direct_br_and_call_target_entries()
	{
		for (int i=0; i < g_num_of_instr_map_entries; i++) {
			if (g_instr_map[i].orig_targ_addr == 0) continue;
			if (g_instr_map[i].hasNewTargAddr) continue;

			for (int j = 0; j < g_num_of_instr_map_entries; j++) {

				if (j == i) continue;

				if (g_instr_map[j].orig_ins_addr == g_instr_map[i].orig_targ_addr) {
					g_instr_map[i].hasNewTargAddr = true;
					g_instr_map[i].new_targ_entry = j;
					break;
				}
			}
		}
		return 0;
	}

	/**************************/
	/* fix_rip_displacement() */
	/**************************/
	int fix_rip_displacement(int instr_map_entry)
	{
		//debug print:
		//dump_instr_map_entry(instr_map_entry);

		xed_decoded_inst_t xedd;
		xed_decoded_inst_zero_set_mode(&xedd,&g_dstate);

		xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(g_instr_map[instr_map_entry].encoded_ins), g_max_inst_len);
		if (xed_code != XED_ERROR_NONE) {
			cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << g_instr_map[instr_map_entry].new_ins_addr << endl;
			return -1;
		}

		unsigned int memops = xed_decoded_inst_number_of_memory_operands(&xedd);

		if (g_instr_map[instr_map_entry].orig_targ_addr != 0)  // a direct jmp or call instruction.
			return 0;

		//cerr << "Memory Operands" << endl;
		bool isRipBase = false;
		xed_reg_enum_t base_reg = XED_REG_INVALID;
		xed_int64_t disp = 0;

		for(unsigned int i=0; i < memops ; i++) {
			base_reg = xed_decoded_inst_get_base_reg(&xedd,i);
			disp = xed_decoded_inst_get_memory_displacement(&xedd,i);

			if (base_reg == XED_REG_RIP) {
				isRipBase = true;
				break;
			}
		}

		if (!isRipBase)
			return 0;

		//xed_uint_t disp_byts = xed_decoded_inst_get_memory_displacement_width(xedd,i); // how many byts in disp ( disp length in byts - for example FFFFFFFF = 4
		xed_int64_t new_disp = 0;
		xed_uint_t new_disp_byts = 4;   // set maximal num of byts for now.

		unsigned int orig_size = xed_decoded_inst_get_length (&xedd);

		// modify rip displacement. use direct addressing mode:
		new_disp = g_instr_map[instr_map_entry].orig_ins_addr + disp + orig_size; // xed_decoded_inst_get_length (&xedd_orig);
		xed_encoder_request_set_base0 (&xedd, XED_REG_INVALID);

		//Set the memory displacement using a bit length
		xed_encoder_request_set_memory_displacement (&xedd, new_disp, new_disp_byts);

		unsigned int size = XED_MAX_INSTRUCTION_BYTES;
		unsigned int new_size = 0;

		// Converts the decoder request to a valid encoder request:
		xed_encoder_request_init_from_decode (&xedd);

		xed_error_enum_t xed_error = xed_encode (&xedd, reinterpret_cast<UINT8*>(g_instr_map[instr_map_entry].encoded_ins), size , &new_size); // &g_instr_map[i].size
		if (xed_error != XED_ERROR_NONE) {
			cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
#if 0
			dump_instr_map_entry(instr_map_entry);
#endif
			return -1;
		}
#if 0
		if (KnobVerbose) {
			dump_instr_map_entry(instr_map_entry);
		}
#endif

		return new_size;
	}

	/************************************/
	/* fix_direct_br_call_to_orig_addr */
	/************************************/
	int fix_direct_br_call_to_orig_addr(int instr_map_entry)
	{
		xed_decoded_inst_t xedd;
		xed_decoded_inst_zero_set_mode(&xedd,&g_dstate);

		xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(g_instr_map[instr_map_entry].encoded_ins), g_max_inst_len);
		if (xed_code != XED_ERROR_NONE) {
			cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << g_instr_map[instr_map_entry].new_ins_addr << endl;
			return -1;
		}

		xed_category_enum_t category_enum = xed_decoded_inst_get_category(&xedd);

		if (category_enum != XED_CATEGORY_CALL && category_enum != XED_CATEGORY_UNCOND_BR) {

			cerr << "ERROR: Invalid direct jump from translated code to original code in rotuine: "
				  << RTN_Name(RTN_FindByAddress(g_instr_map[instr_map_entry].orig_ins_addr)) << endl;
#if 0
			dump_instr_map_entry(instr_map_entry);
#endif
			return -1;
		}

		// check for cases of direct jumps/calls back to the orginal target address:
		if (g_instr_map[instr_map_entry].new_targ_entry >= 0) {
			cerr << "ERROR: Invalid jump or call instruction" << endl;
			return -1;
		}

		unsigned int ilen = XED_MAX_INSTRUCTION_BYTES;
		unsigned int olen = 0;


		xed_encoder_instruction_t  enc_instr;

		ADDRINT new_disp = (ADDRINT)&g_instr_map[instr_map_entry].orig_targ_addr -
						   g_instr_map[instr_map_entry].new_ins_addr -
						   xed_decoded_inst_get_length (&xedd);

		if (category_enum == XED_CATEGORY_CALL)
				xed_inst1(&enc_instr, g_dstate,
				XED_ICLASS_CALL_NEAR, 64,
				xed_mem_bd (XED_REG_RIP, xed_disp(new_disp, 32), 64));

		if (category_enum == XED_CATEGORY_UNCOND_BR)
				xed_inst1(&enc_instr, g_dstate,
				XED_ICLASS_JMP, 64,
				xed_mem_bd (XED_REG_RIP, xed_disp(new_disp, 32), 64));


		xed_encoder_request_t enc_req;

		xed_encoder_request_zero_set_mode(&enc_req, &g_dstate);
		xed_bool_t convert_ok = xed_convert_to_encoder_request(&enc_req, &enc_instr);
		if (!convert_ok) {
			cerr << "conversion to encode request failed" << endl;
			return -1;
		}

		xed_error_enum_t xed_error = xed_encode(&enc_req, reinterpret_cast<UINT8*>(g_instr_map[instr_map_entry].encoded_ins), ilen, &olen);
		if (xed_error != XED_ERROR_NONE) {
			cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
#if 0
			dump_instr_map_entry(instr_map_entry);
#endif
			return -1;
		}

		// handle the case where the original instr size is different from new encoded instr:
		if (olen != xed_decoded_inst_get_length (&xedd)) {

			new_disp = (ADDRINT)&g_instr_map[instr_map_entry].orig_targ_addr -
					   g_instr_map[instr_map_entry].new_ins_addr - olen;

			if (category_enum == XED_CATEGORY_CALL)
				xed_inst1(&enc_instr, g_dstate,
				XED_ICLASS_CALL_NEAR, 64,
				xed_mem_bd (XED_REG_RIP, xed_disp(new_disp, 32), 64));

			if (category_enum == XED_CATEGORY_UNCOND_BR)
				xed_inst1(&enc_instr, g_dstate,
				XED_ICLASS_JMP, 64,
				xed_mem_bd (XED_REG_RIP, xed_disp(new_disp, 32), 64));


			xed_encoder_request_zero_set_mode(&enc_req, &g_dstate);
			xed_bool_t convert_ok = xed_convert_to_encoder_request(&enc_req, &enc_instr);
			if (!convert_ok) {
				cerr << "conversion to encode request failed" << endl;
				return -1;
			}

			xed_error = xed_encode (&enc_req, reinterpret_cast<UINT8*>(g_instr_map[instr_map_entry].encoded_ins), ilen , &olen);
			if (xed_error != XED_ERROR_NONE) {
				cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
#if 0
				dump_instr_map_entry(instr_map_entry);
#endif
				return -1;
			}
		}
#if 0
		// debug prints:
		if (KnobVerbose) {
			dump_instr_map_entry(instr_map_entry);
		}
#endif

		g_instr_map[instr_map_entry].hasNewTargAddr = true;
		return olen;
	}

	/***********************************/
	/* fix_direct_br_call_displacement */
	/***********************************/
	int fix_direct_br_call_displacement(int instr_map_entry)
	{
		xed_decoded_inst_t xedd;
		xed_decoded_inst_zero_set_mode(&xedd,&g_dstate);

		xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(g_instr_map[instr_map_entry].encoded_ins), g_max_inst_len);
		if (xed_code != XED_ERROR_NONE) {
			cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << g_instr_map[instr_map_entry].new_ins_addr << endl;
			return -1;
		}

		xed_int32_t  new_disp = 0;
		unsigned int size = XED_MAX_INSTRUCTION_BYTES;
		unsigned int new_size = 0;

		xed_category_enum_t category_enum = xed_decoded_inst_get_category(&xedd);

		if (category_enum != XED_CATEGORY_CALL && category_enum != XED_CATEGORY_COND_BR && category_enum != XED_CATEGORY_UNCOND_BR) {
			cerr << "ERROR: unrecognized branch displacement" << endl;
			return -1;
		}

		// fix branches/calls to original targ addresses:
		if (g_instr_map[instr_map_entry].new_targ_entry < 0) {
		   int rc = fix_direct_br_call_to_orig_addr(instr_map_entry);
		   return rc;
		}

		ADDRINT new_targ_addr;
		new_targ_addr = g_instr_map[g_instr_map[instr_map_entry].new_targ_entry].new_ins_addr;

		new_disp = (new_targ_addr - g_instr_map[instr_map_entry].new_ins_addr) - g_instr_map[instr_map_entry].size; // orig_size;

		xed_uint_t   new_disp_byts = 4; // num_of_bytes(new_disp);  ???

		// the max displacement size of loop instructions is 1 byte:
		xed_iclass_enum_t iclass_enum = xed_decoded_inst_get_iclass(&xedd);
		if (iclass_enum == XED_ICLASS_LOOP ||  iclass_enum == XED_ICLASS_LOOPE || iclass_enum == XED_ICLASS_LOOPNE) {
		  new_disp_byts = 1;
		}

		// the max displacement size of jecxz instructions is ???:
		xed_iform_enum_t iform_enum = xed_decoded_inst_get_iform_enum (&xedd);
		if (iform_enum == XED_IFORM_JRCXZ_RELBRb){
		  new_disp_byts = 1;
		}

		// Converts the decoder request to a valid encoder request:
		xed_encoder_request_init_from_decode (&xedd);

		//Set the branch displacement:
		xed_encoder_request_set_branch_displacement (&xedd, new_disp, new_disp_byts);

		xed_uint8_t enc_buf[XED_MAX_INSTRUCTION_BYTES];
		unsigned int max_size = XED_MAX_INSTRUCTION_BYTES;

		xed_error_enum_t xed_error = xed_encode (&xedd, enc_buf, max_size , &new_size);
		if (xed_error != XED_ERROR_NONE) {
			cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) <<  endl;
			char buf[2048];
#if 0
			xed_decoded_inst_dump_intel_format(&xedd, buf, 2048, g_instr_map[instr_map_entry].orig_ins_addr);
#endif
			cerr << " instr: " << "0x" << hex << g_instr_map[instr_map_entry].orig_ins_addr << " : " << buf <<  endl;
			return -1;
		}

		new_targ_addr = g_instr_map[g_instr_map[instr_map_entry].new_targ_entry].new_ins_addr;

		new_disp = new_targ_addr - (g_instr_map[instr_map_entry].new_ins_addr + new_size);  // this is the correct displacemnet.

		//Set the branch displacement:
		xed_encoder_request_set_branch_displacement (&xedd, new_disp, new_disp_byts);

		xed_error = xed_encode (&xedd, reinterpret_cast<UINT8*>(g_instr_map[instr_map_entry].encoded_ins), size , &new_size); // &g_instr_map[i].size
		if (xed_error != XED_ERROR_NONE) {
			cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
#if 0
			dump_instr_map_entry(instr_map_entry);
#endif
			return -1;
		}

#if 0
		//debug print of new instruction in tc:
		if (KnobVerbose) {
			dump_instr_map_entry(instr_map_entry);
		}
#endif

		return new_size;
	}

	/************************************/
	/* fix_instructions_displacements() */
	/************************************/
	int fix_instructions_displacements()
	{
	   // fix displacemnets of direct branch or call instructions:

		int size_diff = 0;

		do {
			size_diff = 0;

			if (KnobVerbose) {
				cerr << "starting a pass of fixing instructions displacements: " << endl;
			}

			for (int i=0; i < g_num_of_instr_map_entries; i++) {
				g_instr_map[i].new_ins_addr += size_diff;

				int rc = 0;

				// fix rip displacement:
				rc = fix_rip_displacement(i);
				if (rc < 0)
					return -1;

				if (rc > 0) { // this was a rip-based instruction which was fixed.

					if (g_instr_map[i].size != (unsigned int)rc) {
					   size_diff += (rc - g_instr_map[i].size);
					   g_instr_map[i].size = (unsigned int)rc;
					}

					continue;
				}

				// check if it is a direct branch or a direct call instr:
				if (g_instr_map[i].orig_targ_addr == 0) {
					continue;  // not a direct branch or a direct call instr.
				}

				// fix instr displacement:
				rc = fix_direct_br_call_displacement(i);
				if (rc < 0)
					return -1;

				if (g_instr_map[i].size != (unsigned int)rc) {
				   size_diff += (rc - g_instr_map[i].size);
				   g_instr_map[i].size = (unsigned int)rc;
				}
			}  // end int i=0; i ..
		} while (size_diff != 0);

	   return 0;
	}

	/*****************************************/
	/* find_candidate_rtns_for_translation() */
	/*****************************************/
	int find_candidate_rtns_for_translation(IMG img)
	{
		int rc;

		// go over routines and check if they are candidates for translation and mark them for translation:
		for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
		{
			if (!SEC_IsExecutable(sec) || SEC_IsWriteable(sec) || !SEC_Address(sec))
				continue;

			for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
			{
				if (rtn == RTN_Invalid()) {
				  cerr << "Warning: invalid routine " << RTN_Name(rtn) << endl;
				  continue;
				}
				
				bool is_top_ten = false;
				for (unsigned int i = 0; i < common::TEN; ++i)
					if (common::g_top_ten[i] == RTN_Address(rtn)) is_top_ten = true;
				
				if (!is_top_ten) continue;
				
				g_translated_rtn[g_translated_rtn_num].rtn_addr = RTN_Address(rtn);
				g_translated_rtn[g_translated_rtn_num].rtn_size = RTN_Size(rtn);
				g_translated_rtn[g_translated_rtn_num].instr_map_entry = g_num_of_instr_map_entries;
				g_translated_rtn[g_translated_rtn_num].isSafeForReplacedProbe = true;

				// Open the RTN.
				RTN_Open( rtn );

				for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) {
					//debug print of orig instruction:
					if (KnobVerbose) {
						cerr << "old instr: ";
						cerr << "0x" << hex << INS_Address(ins) << ": " << INS_Disassemble(ins) <<  endl;
						//xed_print_hex_line(reinterpret_cast<UINT8*>(INS_Address (ins)), INS_Size(ins));
					}

					ADDRINT addr = INS_Address(ins);

					xed_decoded_inst_t xedd;
					xed_error_enum_t xed_code;

					xed_decoded_inst_zero_set_mode(&xedd,&g_dstate);

					xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(addr), g_max_inst_len);
					if (xed_code != XED_ERROR_NONE) {
						cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << addr << endl;
						g_translated_rtn[g_translated_rtn_num].instr_map_entry = -1;
						break;
					}

					// Add instr into instr map:
					rc = add_new_instr_entry(&xedd, INS_Address(ins), INS_Size(ins));
					if (rc < 0) {
						cerr << "ERROR: failed during instructon translation." << endl;
						g_translated_rtn[g_translated_rtn_num].instr_map_entry = -1;
						break;
					}
				} // end for INS...

				// debug print of routine name:
				if (KnobVerbose) {
					cerr <<   "rtn name: " << RTN_Name(rtn) << " : " << dec << g_translated_rtn_num << endl;
				}

				// Close the RTN.
				RTN_Close( rtn );

				g_translated_rtn_num++;
			 } // end for RTN..
		} // end for SEC...

		return 0;
	}

	/***************************/
	/* int copy_instrs_to_tc() */
	/***************************/
	int copy_instrs_to_tc()
	{
		int cursor = 0;
		for (int i=0; i < g_num_of_instr_map_entries; i++) {
		  if ((ADDRINT)&g_tc[cursor] != g_instr_map[i].new_ins_addr) {
			  cerr << "ERROR: Non-matching instruction addresses: " << hex << (ADDRINT)&g_tc[cursor] << " vs. " << g_instr_map[i].new_ins_addr << endl;
			  return -1;
		  }

		  memcpy(&g_tc[cursor], &g_instr_map[i].encoded_ins, g_instr_map[i].size);
		  cursor += g_instr_map[i].size;
		}

		return 0;
	}

	/*************************************/
	/* void commit_translated_routines() */
	/*************************************/
	inline void commit_translated_routines()
	{
		// Commit the translated functions:
		// Go over the candidate functions and replace the original ones by their new successfully translated ones:
		for (int i=0; i < g_translated_rtn_num; i++) {
			//replace function by new function in tc
			if (g_translated_rtn[i].instr_map_entry >= 0) {
				if (g_translated_rtn[i].rtn_size > MAX_PROBE_JUMP_INSTR_BYTES && g_translated_rtn[i].isSafeForReplacedProbe) {
					RTN rtn = RTN_FindByAddress(g_translated_rtn[i].rtn_addr);

					//debug print:
					if (rtn == RTN_Invalid()) {
						cerr << "committing rtN: Unknown";
					} else {
						cerr << "committing rtN: " << RTN_Name(rtn);
					}
					cerr << " from: 0x" << hex << RTN_Address(rtn) << " to: 0x" << hex << g_instr_map[g_translated_rtn[i].instr_map_entry].new_ins_addr << endl;

					if (RTN_IsSafeForProbedReplacement(rtn)) {

						AFUNPTR origFptr = RTN_ReplaceProbed(rtn,  (AFUNPTR)g_instr_map[g_translated_rtn[i].instr_map_entry].new_ins_addr);

						if (origFptr == NULL) {
							cerr << "RTN_ReplaceProbed failed.";
						} else {
							cerr << "RTN_ReplaceProbed succeeded. ";
						}
						cerr << " orig routine addr: 0x" << hex << g_translated_rtn[i].rtn_addr
								<< " replacement routine addr: 0x" << hex << g_instr_map[g_translated_rtn[i].instr_map_entry].new_ins_addr << endl;
#if 0
						dump_instr_from_mem ((ADDRINT *)g_translated_rtn[i].rtn_addr, g_translated_rtn[i].rtn_addr);
#endif
					}
				}
			}
		}
	}

	/****************************/
	/* allocate_and_init_memory */
	/****************************/
	int allocate_and_init_memory(IMG img)
	{
		// Calculate size of executable sections and allocate required memory:
		//
		for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
		{
			if (!SEC_IsExecutable(sec) || SEC_IsWriteable(sec) || !SEC_Address(sec))
				continue;

			if (!g_lowest_sec_addr || g_lowest_sec_addr > SEC_Address(sec))
				g_lowest_sec_addr = SEC_Address(sec);

			if (g_highest_sec_addr < SEC_Address(sec) + SEC_Size(sec))
				g_highest_sec_addr = SEC_Address(sec) + SEC_Size(sec);

			// need to avouid using RTN_Open as it is expensive...
			for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
			{
				if (rtn == RTN_Invalid()) continue;

				g_max_ins_count += RTN_NumIns  (rtn);
				g_max_rtn_count++;
			}
		}

		g_max_ins_count *= 4; // estimating that the num of instrs of the inlined functions will not exceed the total nunmber of the entire code.

		// Allocate memory for the instr map needed to fix all branch targets in translated routines:
		g_instr_map = (instr_map_t *)calloc(g_max_ins_count, sizeof(instr_map_t));
		if (g_instr_map == NULL) {
			perror("calloc");
			return -1;
		}

		// Allocate memory for the array of candidate routines containing inlineable function calls:
		// Need to estimate size of inlined routines.. ???
		g_translated_rtn = (translated_rtn_t *)calloc(g_max_rtn_count, sizeof(translated_rtn_t));
		if (g_translated_rtn == NULL) {
			perror("calloc");
			return -1;
		}

		// get a page size in the system:
		int pagesize = sysconf(_SC_PAGE_SIZE);
		if (pagesize == -1) {
		  perror("sysconf");
		  return -1;
		}

		ADDRINT text_size = (g_highest_sec_addr - g_lowest_sec_addr) * 2 + pagesize * 4;

		int tclen = 2 * text_size + pagesize * 4;   // need a better estimate???

		// Allocate the needed tc with RW+EXEC permissions and is not located in an address that is more than 32bits afar:
		char * addr = (char *) mmap(NULL, tclen, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
		if ((ADDRINT) addr == 0xffffffffffffffff) {
			cerr << "failed to allocate tc" << endl;
			return -1;
		}

		g_tc = (char *)addr;
		return 0;
	}

	/* ============================================ */
	/* Main translation routine                     */
	/* ============================================ */
	VOID ImageLoad(IMG img, VOID *v)
	{
		// debug print of all images' instructions
		//dump_all_image_instrs(img);

		// Step 0: Check the image and the CPU:
		if (!IMG_IsMainExecutable(img))
			return;

		int rc = 0;

		// step 1: Check size of executable sections and allocate required memory:
		rc = allocate_and_init_memory(img);
		if (rc < 0)
			return;

		//cout << "after memory allocation" << endl;

		// Step 2: go over all routines and identify candidate routines and copy their code into the instr map IR:
		rc = find_candidate_rtns_for_translation(img);
		if (rc < 0)
			return;

		//cout << "after identifying candidate routines" << endl;

		// Step 3: Chaining - calculate direct branch and call instructions to point to corresponding target instr entries:
		rc = chain_all_direct_br_and_call_target_entries();
		if (rc < 0 )
			return;

		//cout << "after calculate direct br targets" << endl;

		// Step 4: fix rip-based, direct branch and direct call displacements:
		rc = fix_instructions_displacements();
		if (rc < 0 )
			return;

		//cout << "after fix instructions displacements" << endl;


		// Step 5: write translated routines to new tc:
		rc = copy_instrs_to_tc();
		if (rc < 0 )
			return;

		//cout << "after write all new instructions to memory tc" << endl;
#if 0
	   if (KnobDumpTranslatedCode) {
		   cerr << "Translation Cache dump:" << endl;
		   dump_tc();  // dump the entire tc

		   cerr << endl << "instructions map dump:" << endl;
		   dump_entire_instr_map();     // dump all translated instructions in map_instr
	   }
#endif

		// Step 6: Commit the translated routines:
		//Go over the candidate functions and replace the original ones by their new successfully translated ones:
		commit_translated_routines();

		//cout << "after commit translated routines" << endl;
	}
}

namespace project {
	/* ===================================================================== */
	/* Names of malloc and free */
	/* ===================================================================== */
	#define MALLOC "malloc"
	#define FREE "free"
	#define MAIN "main"

	/* ===================================================================== */
	/* Global Variables */
	/* ===================================================================== */

	std::ostream& TraceFile = std::cout;
	bool mainInit = false;
	bool mainFinished = false;
	ADDRINT lastMallocSize;
	Tracer mallocTracer = Tracer::GetInstance();
	set<ADDRINT> suspiciousAddresses;

	/* ===================================================================== */
	/* Commandline Switches */
	/* ===================================================================== */

	KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
		"o", "malloctrace.out", "specify trace file name");

	/* ===================================================================== */
	bool IsCalledAfterMain()
	{
		// Don't run instumentation code unless main has started
		return (mainInit && !mainFinished);
	}

	/* ===================================================================== */
	/* Analysis routines                                                     */
	/* ===================================================================== */
	VOID Arg1Before(CHAR * name, ADDRINT size)
	{
		if (!IsCalledAfterMain()) return;
		lastMallocSize = size;
	}

	VOID AfterFree(CHAR * name, ADDRINT addr)
	{
		if (!IsCalledAfterMain()) return;
		mallocTracer.DeleteAddress(addr);
	}

	VOID MallocAfter(ADDRINT ret)
	{
		if (!IsCalledAfterMain()) return;		
		mallocTracer.AddNewAddress(ret, lastMallocSize);
	}

	VOID mainBefore() { mainInit = true; }
	VOID mainAfter()  { mainFinished = true; }

	// Print a memory read record
	VOID RecordMemRead(VOID * ip, ADDRINT addr)
	{
		if (!IsCalledAfterMain()) return;
		if (suspiciousAddresses.count((ADDRINT)ip) !=0)
			cout << "Memory read overflow at address: 0x" << hex << (ADDRINT)ip << dec << endl;
	}

	// Print a memory write record
	VOID RecordMemWrite(VOID* ip, ADDRINT addr)
	{
		if (!IsCalledAfterMain()) return;
		if (suspiciousAddresses.count((ADDRINT)ip) !=0)
			cout << "Memory write overflow at address: 0x" << hex << (ADDRINT)ip << dec << endl;
	}

	VOID CheckAddIns(ADDRINT regVal, UINT64 immediate, VOID* ip, UINT64 insSize)
	{
		if (!mallocTracer.IsAllocatedAddress(regVal)) return;
		if (mallocTracer.GetStartAddress(regVal + immediate) != mallocTracer.GetStartAddress(regVal))
			suspiciousAddresses.insert(ADDRINT(ip) + insSize);
	}

	bool INS_IsAdd(INS ins)
	{
		string insDisassembly = INS_Disassemble(ins);
		return (insDisassembly.substr(0, 3) == "add");
	}

	VOID CheckAddInsIndexReg(ADDRINT regVal, ADDRINT indexRegVal, VOID* ip, UINT64 insSize)
	{
		if (!mallocTracer.IsAllocatedAddress(regVal)) return;			
		if (mallocTracer.GetStartAddress(regVal + indexRegVal) != mallocTracer.GetStartAddress(regVal))
			suspiciousAddresses.insert(ADDRINT(ip) + insSize);
	}

	/* ===================================================================== */
	/* Instrumentation routines                                              */
	/* ===================================================================== */
	   
	VOID Image(IMG img, VOID *v)
	{
		// Instrument the malloc() and free() functions.  Print the input argument
		// of each malloc() or free(), and the return value of malloc().
		//
		//  Find the malloc() function.
		RTN mallocRtn = RTN_FindByName(img, MALLOC);
		if (RTN_Valid(mallocRtn))
		{
			RTN_Open(mallocRtn);

			RTN_InsertCall(mallocRtn, IPOINT_BEFORE, (AFUNPTR)Arg1Before,
						   IARG_ADDRINT, MALLOC,
						   IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
						   IARG_END);
						   
			RTN_InsertCall(mallocRtn, IPOINT_AFTER, (AFUNPTR)MallocAfter,
						   IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

			RTN_Close(mallocRtn);
		}

		// Find the free() function.
		RTN freeRtn = RTN_FindByName(img, FREE);
		if (RTN_Valid(freeRtn))
		{
			RTN_Open(freeRtn);
			// Instrument free()
			RTN_InsertCall(freeRtn, IPOINT_AFTER, (AFUNPTR)AfterFree,
						   IARG_ADDRINT, FREE,
						   IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
						   IARG_END);
			RTN_Close(freeRtn);
		}
		
		RTN mainRtn = RTN_FindByName(img, MAIN);
		if (RTN_Valid(mainRtn))
		{
			RTN_Open(mainRtn);
			
			RTN_InsertCall(mainRtn, IPOINT_BEFORE, (AFUNPTR)mainBefore, IARG_END);
			RTN_InsertCall(mainRtn, IPOINT_AFTER, (AFUNPTR)mainAfter, IARG_END);
			
			RTN_Close(mainRtn);
		}
	}

	// Pin calls this function every time a new rtn is executed
	VOID Routine(RTN rtn, VOID *v)
	{
		//if (!IMG_IsMainExecutable(IMG_FindByAddress(RTN_Address(rtn)))) return;
		cout << "Routine rtn=" << RTN_Name(rtn) << std::endl;
		cout << "Routine img=" << IMG_Name(IMG_FindByAddress(RTN_Address(rtn))) << std::endl;
			
		RTN_Open(rtn);
		// For each instruction of the routine
		for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
		{
			if (INS_IsAdd(ins))
			{
				UINT32 opNum = INS_OperandCount(ins);
				UINT64 immediate = 0;
				REG operandReg = REG_INVALID();
				REG indexReg = REG_INVALID();
				bool foundReg = false;
				bool foundIndexReg = false;
				bool foundImm = false;

				for (UINT32 i = 0; i < opNum; ++i)
				{
					if (!foundImm && INS_OperandIsImmediate(ins, i))
					{
						immediate = INS_OperandImmediate(ins, i);
						foundImm = true;
					}
					
					else if (!foundReg && INS_OperandIsReg(ins, i) && INS_OperandWritten(ins, i))
					{
						operandReg = INS_OperandReg(ins, i);
						if (REG_INVALID() != operandReg )
							foundReg = true;
					}
					
					else if (!foundIndexReg && INS_OperandIsReg(ins, i) && INS_OperandReadOnly(ins, i))
					{
						indexReg = INS_OperandReg(ins, i);
						if (REG_INVALID() != indexReg)
							foundIndexReg = true;
					}

					if (foundReg && foundImm && REG_valid_for_iarg_reg_value(operandReg))
					{
						INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)CheckAddIns, 
							IARG_REG_VALUE, operandReg, IARG_UINT64, immediate,
							IARG_INST_PTR, IARG_UINT64, INS_Size(ins), IARG_END);
						break;
					}
					
					else if (foundIndexReg && foundReg && REG_valid_for_iarg_reg_value(operandReg)
						&& REG_valid_for_iarg_reg_value(indexReg))
					{
						INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)CheckAddInsIndexReg, 
							IARG_REG_VALUE, operandReg, IARG_REG_VALUE, indexReg,
							IARG_INST_PTR, IARG_UINT64, INS_Size(ins), IARG_END);
						break;
					}
				}
			} 
			else 
			{
				UINT32 memOperands = INS_MemoryOperandCount(ins);

				// Iterate over each memory operand of the instruction.
				for (UINT32 memOp = 0; memOp < memOperands; memOp++)
				{
					if (INS_MemoryOperandIsRead(ins, memOp))
					{
						 INS_InsertCall(
							ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead,
							IARG_INST_PTR,
							IARG_MEMORYOP_EA, memOp,
							IARG_END);
					}
					
					// Note that in some architectures a single memory operand can be 
					// both read and written (for instance incl (%eax) on IA-32)
					// In that case we instrument it once for read and once for write.
					if (INS_MemoryOperandIsWritten(ins, memOp))
					{
						 INS_InsertCall(
							ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite,
							IARG_INST_PTR,
							IARG_MEMORYOP_EA, memOp,
							IARG_UINT64, INS_Size(ins),
							IARG_END);
					}
				}
			}
		}
		RTN_Close(rtn);
	}

}

KNOB<BOOL> KnobProf(KNOB_MODE_WRITEONCE, "pintool", "prof", "0", "generate profile");
KNOB<BOOL> KnobInst(KNOB_MODE_WRITEONCE, "pintool", "inst" , "0", "instrument binary");
KNOB<BOOL> KnobProj(KNOB_MODE_WRITEONCE, "pintool", "proj" , "0", "project");

INT32 Usage()
{
    std::cerr << "Usage: pin -t ex3.so -prof|inst -- <executable>" << std::endl;
    return -1;
}

int main(int argc, char *argv[])
{
	PIN_InitSymbols();
	if(PIN_Init(argc,argv)) return Usage();
	if (!!KnobProf + !!KnobInst + !!KnobProj != 1) return Usage();

	if (KnobProf)
	{
		TRACE_AddInstrumentFunction(ex2::Trace, 0);
		IMG_AddInstrumentFunction(ex2::Img, 0);
		PIN_AddFiniFunction(ex2::Fini, 0);

		PIN_StartProgram();
	}

	if (KnobInst)
	{
		ex3::read_top10("__profile.map");
		IMG_AddInstrumentFunction(ex3::ImageLoad, 0);
		PIN_StartProgramProbed();
	}
	
	if (KnobProj)
	{
		// Register Image to be called to instrument functions.
		IMG_AddInstrumentFunction(project::Image, 0);
		RTN_AddInstrumentFunction(project::Routine, 0);
		//PIN_StartProgramProbed();
		PIN_StartProgram();
	}

	return 0;
}
