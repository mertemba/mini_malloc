CXX = afl-c++
CC = afl-cc

mini_malloc.a: ../mini_malloc.c
	$(CC) -O2 -g $^ -c -o $@

fuzzer: fuzzer.cpp mini_malloc.a
	$(CXX) -O2 -g $^ -o $@

fuzz: fuzzer
	AFL_SKIP_CPUFREQ=1 afl-fuzz -m 180000 -t 100 -x mini_malloc.dict -i in -o out ./fuzzer

fuzz_parallel: fuzzer
	AFL_SKIP_CPUFREQ=1 nohup afl-fuzz -m 180000 -t 100 -x mini_malloc.dict -i in -o out -M fuzzer01 ./fuzzer &
	sleep 0.5
	AFL_SKIP_CPUFREQ=1 nohup afl-fuzz -m 180000 -t 100 -x mini_malloc.dict -i in -o out -S fuzzer02 ./fuzzer &
	AFL_SKIP_CPUFREQ=1 nohup afl-fuzz -m 180000 -t 100 -x mini_malloc.dict -i in -o out -S fuzzer03 ./fuzzer &
	AFL_SKIP_CPUFREQ=1 nohup afl-fuzz -m 180000 -t 100 -x mini_malloc.dict -i in -o out -S fuzzer04 ./fuzzer &
	AFL_SKIP_CPUFREQ=1 nohup afl-fuzz -m 180000 -t 100 -x mini_malloc.dict -i in -o out -S fuzzer05 ./fuzzer &
	AFL_SKIP_CPUFREQ=1 nohup afl-fuzz -m 180000 -t 100 -x mini_malloc.dict -i in -o out -S fuzzer06 ./fuzzer &
	AFL_SKIP_CPUFREQ=1 nohup afl-fuzz -m 180000 -t 100 -x mini_malloc.dict -i in -o out -S fuzzer07 ./fuzzer &
	AFL_SKIP_CPUFREQ=1 nohup afl-fuzz -m 180000 -t 100 -x mini_malloc.dict -i in -o out -S fuzzer08 ./fuzzer &

clean:
	rm -f fuzzer