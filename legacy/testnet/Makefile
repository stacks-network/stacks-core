INDEX_HTML := index.html
INDEX_CSS := $(wildcard *.css)
INDEX_JS = $(wildcard *.js)
WWWDIR := www

INDEX_FILES := $(INDEX_HTML) $(INDEX_CSS) $(INDEX_JS)

SITE_FILES := $(patsubst %,$(WWWDIR)/%,$(INDEX_FILES))
SITE_INDEX_HTML := $(WWWDIR)/$(INDEX_HTML)

all: $(SITE_FILES)

$(WWWDIR):
	mkdir -p "$@"

$(SITE_INDEX_HTML): $(INDEX_HTML).py $(WWWDIR)
	./"$<" > $@

$(WWWDIR)/%.css: %.css $(WWWDIR)
	cp -a $< $@

$(WWWDIR)/%.js: %.js $(WWWDIR)
	cp -a $< $@

.PHONY: test
test:
	$(SHELL) -c "cd "$(WWWDIR)" && python ../test/testServer.py"

.PHONY: mocktest
mocktest:
	$(SHELL) -c "cd "$(WWWDIR)" && MOCK=1 python ../test/testServer.py"

clean:
	rm -rf "$(WWWDIR)"

print-%: ; @echo $*=$($*)

