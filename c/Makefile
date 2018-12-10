SUBDIRS := $(wildcard */.)

all: $(SUBDIRS)
$(SUBDIRS):
	$(MAKE) -C $@

.PHONY: all $(SUBDIRS)

.PHONY: clean 
clean:
	ROOT=`/bin/pwd`; \
    for dir in `find . ! -path . -type d -print`; \
    do \
		echo $$dir; \
		make -C "$${dir}" -f "$${ROOT}"/Makefile clean; \
	done
