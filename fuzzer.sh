mkdir -p out

rm -rf out/*

export AFL_SKIP_CPUFREQ=1 
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1  
export AFL_SKIP_BIN_CHECK=1  

afl-fuzz -i in -o out -m none -t 1000+ -d -p fast -- ./target @@
