#include "elliptic_group.h";
#include <iostream>
using namespace std;

int reverse_mod(int value, int mod) {
	if (value < 0) {
		value += mod;
	}

	int q;
	int r_0, r_1, r_2;
	int x_0, x_1, x_2;
	int y_0, y_1, y_2;

	r_0 = mod; r_1 = value;
	x_0 = 1; x_1 = 0;
	y_0 = 0; y_1 = 1;


	while (r_1) {
		q = r_0 / r_1;
		r_2 = r_0 - q*r_1;
		x_2 = x_0 - q*x_1;
		y_2 = y_0 - q*y_1;

		r_0 = r_1; r_1 = r_2;
		x_0 = x_1; x_1 = x_2;
		y_0 = y_1; y_1 = y_2;
	}

	if (y_0 < 0) {
		y_0 += mod;
	}
	return y_0;
}

point add_points(point P, point Q, int a, int mod) {
	point R;
	if (P.x == -1) {
		return Q;
	}
	if (Q.x == -1) {
		return P;
	}
	int lambda;
	if (P.x == Q.x) {
		if (((P.y + Q.y) % mod) == 0) {
			R.x = R.y = -1;
			return R;
		}
		lambda = (3 * P.x * P.x + a) * reverse_mod((2 * P.y), mod);
	}
	else {
		lambda = (Q.y - P.y) * reverse_mod((Q.x - P.x), mod);
	}
	lambda %= mod;
	if (lambda < 0) {
		lambda += mod;
	}

	R.x = (lambda*lambda - P.x - Q.x) % mod;
	if (R.x < 0) {
		R.x += mod;
	}
	R.y = ((lambda*(P.x - R.x) - P.y)) % mod;
	if (R.y < 0) {
		R.y += mod;
	}

	return R;
}

point multiply_point(point P, int number, int a, int mod) {
	point R = P;
	if (number == 0) {
		return point{ -1,-1 };
	}
	for (int i = 2; i <= number; i++) {
		R = add_points(R, P, a, mod);
	}
	return R;
}

void elliptic_group::generate_secret_key() {
	secret_key = rand() % (order_of_G - 1) + 1;
}

void elliptic_group::generate_public_key() {
	public_key = multiply_point(G, secret_key, a, module);
}

bool elliptic_group::read(uint8_t* message) {
	ifstream input(filename);
	input >> public_key.x;
	if (public_key.x == EOF) {
		return false;
	}
	input >> public_key.y;
	input >> signature.r;
	input >> signature.s;
	input.getline((char*)message, 255);
	return true;
}

void elliptic_group::write(uint8_t* message) {
	ofstream output(filename);
	output << public_key.x << " " << public_key.y<<" ";
	output << signature.r << " " << signature.s<<" ";
	output <<(char*) message << endl;
	output.close();
}

uint32_t murmur3_32(const uint8_t* key, size_t len, uint32_t seed = 0xB0F57EE3) {
	uint32_t h = seed;
	if (len > 3) {
		const uint32_t* key_x4 = (const uint32_t*)key;
		size_t i = len >> 2;
		do {
			uint32_t k = *key_x4++;
			k *= 0xcc9e2d51;
			k = (k << 15) | (k >> 17);
			k *= 0x1b873593;
			h ^= k;
			h = (h << 13) | (h >> 19);
			h = (h * 5) + 0xe6546b64;
		} while (--i);
		key = (const uint8_t*)key_x4;
	}
	if (len & 3) {
		size_t i = len & 3;
		uint32_t k = 0;
		key = &key[i - 1];
		do {
			k <<= 8;
			k |= *key--;
		} while (--i);
		k *= 0xcc9e2d51;
		k = (k << 15) | (k >> 17);
		k *= 0x1b873593;
		h ^= k;
	}
	h ^= len;
	h ^= h >> 16;
	h *= 0x85ebca6b;
	h ^= h >> 13;
	h *= 0xc2b2ae35;
	h ^= h >> 16;
	return h;
}

void elliptic_group::sign(uint8_t* message) {
	int k;
	point kG;
	while (true) {
		
		k = rand() % (order_of_G - 3) + 2;
		kG = multiply_point(G, k, a, module);
		signature.r = kG.x%order_of_G;

		if (signature.r != 0) {
			signature.s = murmur3_32((const uint8_t*)message, strlen((char*)message)) % order_of_G;
			signature.s += (secret_key*signature.r);
			signature.s %= order_of_G;
			signature.s *= reverse_mod(k, order_of_G);
			signature.s %= order_of_G;
			if (signature.s < 0) {
				signature.s += order_of_G;
			}
			if (signature.s != 0) {
				break;
			}
			
		}
	}
}

bool elliptic_group::verify(uint8_t* message) {
	

	int w, u1, u2, _r;
	point u1G, u2Pa, sum;

	if (signature.r < 1 || signature.r > (order_of_G - 1) ||
		signature.s < 1 || signature.s > (order_of_G - 1)) {
		return false;
	}
	w = reverse_mod(signature.s, order_of_G);
		
	for (int i = 0; i <= strlen((char*)message); i++) {
		message[i] = message[i + 1];
		
	}

	u1 = murmur3_32((const uint8_t*)message, strlen((char*)message)) % order_of_G;	
	u1 *= w;
	u1 %= order_of_G;
	if (u1 < 0) {
		u1 += order_of_G;
	}
	
	u2 = (signature.r*w) % order_of_G;
	
	u1G = multiply_point(G, u1, a, module);
	
	u2Pa = multiply_point(public_key, u2, a, module);
	sum = add_points(u1G, u2Pa, a, module);
	
	_r = sum.x%order_of_G;
	
	if (_r == signature.r) {
		return true;
	}
	return false;
}