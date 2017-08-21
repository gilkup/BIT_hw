Marina Minkin 307659318
Gil Kupfer 201112919

compile:
In the directory of the pintool:
	"make PIN_ROOT=<pin directory>"
The pintool source can be in any directory rather than only in a subdir of pin.

run:
In the directory of the pintool:
	"<pin directory>/pin -t <pintool binary directory>/project.so -- ./bzip2 -k -f ./input-long.txt"

