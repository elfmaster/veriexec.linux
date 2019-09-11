all:
	gcc -DDEBUG -g veriexec_client.c -o veriexec_client /opt/elfmaster/lib/libelfmaster.a -lssl -lcrypto
clean:
	rm -rf veriexec_client
