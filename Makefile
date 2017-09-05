nf_queue_test : nf_queue_test.c
	gcc -g -lnfnetlink -lnetfilter_queue $< -o $@

clean :
	rm -f nf_queue_test

