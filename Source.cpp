#include <iostream>
#include "elliptic_group.h"

using namespace std;

void sign() {
	cout << "sign\n";
	elliptic_group E;
	char filename[8];
	uint8_t message[256];

	cout << "Enter file name: ";
	cin >> filename;
	E.set_filename(filename);

	cout << "Enter your message: ";
	cin.ignore(std::numeric_limits<size_t>::max(), '\n');
	cin.getline((char*)message, 255);

	E.generate_secret_key();
	cout << "secret key was generated\n";
	E.generate_public_key();
	cout << "public key was generated\n";

	E.sign(message);
	cout << "message was signed\n";
	E.write(message);
	cout << "data was written\n";
}

void verify() {
	cout << "verify\n";
	elliptic_group E;
	char filename[8];
	uint8_t message[256];

	cout << "Enter file name: ";
	cin >> filename;
	E.set_filename(filename);

	E.read(message);
	cout << "data was read\n";


	if (E.verify(message)) {
		cout << "signature is correct, message can be trusted\n";
	}
	else {
		cout << "signature is INcorrect, message can NOT be trusted\n";

	}
	cout << "message: " << (char*)message << endl;

}

int main() {
	srand(time(NULL));
	int c;
	cout << "Hello\n";
	do {
		cout << "Press 4 to sign, 6 to verify or 0 to exit: ";
		cin >> c;
		switch (c) {
		case 0: return 0;
		case 4: sign(); break;
		case 6: verify(); break;
		default: cout << "No, try again\n";
		}
	} while (true);

}