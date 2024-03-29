.DEFAULT_GOAL := build

out_dir:
	if [ ! -d out ]; then mkdir out; fi

build: out_dir
	go build -o out/ldapswissknife src/* 

clean: out_dir
	if [ -e out/ldapswissknife ]; then rm out/ldapswissknife; fi
