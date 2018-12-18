SUBDIRS := $(wildcard */.)

all: $(SUBDIRS)
$(SUBDIRS):
	$(MAKE) -C $@

.PHONY: all $(SUBDIRS)

.PHONY: clean 
clean:
	for dir in $(SUBDIRS); do \
    	$(MAKE) -C $$dir -f Makefile $@; \
    done	
