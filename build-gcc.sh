echo Building \'ZIPValidateCRC-`uname -m`\' ...
gcc -std=c++11 ZIPValidateCRC.cpp -lstdc++ -Wall -o ZIPValidateCRC-`uname -m`
echo Done!