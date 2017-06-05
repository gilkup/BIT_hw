#include "pin.H"

#include <assert.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

#include <fstream>
#include <string>
#include <set>
#include <map>
#include <iostream> // TODO: delete this line
#include <algorithm>


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

VOID Img(IMG img, VOID *v) // why VOID *v ?
{
	g_img_map[IMG_Name(img)] = IMG_LowAddress(img);
}

#pragma pack(1)
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

	for(std::set<printing_rtn_t, cmp_printing_rtn>::iterator print_it = printing_ds_sorted.begin() ; print_it != printing_ds_sorted.end() ; ++print_it) {
		// TODO: this is not sorted by the counter
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

VOID Fini(INT32 code, VOID *v)
{
	update_file("__profile.map");
	print("rtn-output.txt");
}

int main(int argc, char *argv[])
{
	PIN_InitSymbols();
	if(PIN_Init(argc,argv)) return -1;
    
	TRACE_AddInstrumentFunction(Trace, 0);
	IMG_AddInstrumentFunction(Img, 0);
	PIN_AddFiniFunction(Fini, 0);

	PIN_StartProgram();
    
	return 0;
}

