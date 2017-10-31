#pragma once
#include <fstream>
#include <time.h>

#define FILENAME_LENGTH 12

struct point {
	int x;
	int y;
};

struct signature {
	int r;
	int s;
};

class elliptic_group {
private:
	int module;
	int a;
	int b;
	point G;
	int order_of_G;
	int secret_key;
	char filename[FILENAME_LENGTH];
public:
	point public_key;
	signature signature;
	elliptic_group() {
		module = 71;
		a = 27;
		b = 39;
		G = point{ 38,29 };
		order_of_G = 13;
	}

	void set_filename(char* _filename) {
		for (int i = 0; i < FILENAME_LENGTH; i++) {
			filename[i] = _filename[i];
		}
	}
	void generate_secret_key();
	void generate_public_key();
	bool read(uint8_t* message);
	void write(uint8_t* message);
	//void generate_common_key();
	void sign(uint8_t* message);
	bool verify(uint8_t* message);
	
};