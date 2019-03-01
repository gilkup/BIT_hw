Marina Minkin
Gil Kupfer

compile:
In the directory of the pintool:
	"make PIN_ROOT=<pin directory>"
The pintool source can be in any directory rather than only in a subdir of pin.

run:
In the directory of the pintool:
	"<pin directory>/pin -t <pintool binary directory>/ex3.so -inst/prof -- ./bzip2 -k -v ./input.txt"

--
Pintool binary directory is usually obj-intel64 in src (when compiling there).

The output is in rtn-output.txt/__profile_map files.
When using "inst", list of the top ten function will be printed to cerr.

The top ten functions are only from the main executable as discussed in class.
