.PHONY: default build cleantemp clean graphics

SRC=main.tex
BUILD_DIR=build
NAME=main

default: main

main: | $(NAME).pdf

clean: clean-temp clean-target

clean-target: 
	rm -f *.pdf *.pdfsync *.pdfsync.gz *.log

clean-temp:
	rm -f *.acn *.acr *.alg *.aux *.bbl *.blg *.dvi *.glg *.glo *.gls *.ist \
	      *.lof *.lol *.lot *.out *.tdo *.toc *.tdo *.xml *.bcf *.nav *.snm
	rm -rf $(BUILD_DIR)

%.pdf: $(BUILD_DIR)/%.tex
	latexmk -pdf -outdir=$(BUILD_DIR) \
			-latexoption=-interaction=nonstopmode \
			-latexoption=-halt-on-error \
			-latexoption=-file-line-error \
	$<
	cp $(BUILD_DIR)/$@ .

$(BUILD_DIR)/main.tex: $(BUILD_DIR) $(SRC) bib
	cp $(SRC) $@

$(BUILD_DIR) :
	mkdir -p $(BUILD_DIR)

bib:
	[ -h bib/bibliography.bib ] && cp -uL bib/bibliography.bib || true

help:
	@echo "make:         Build paper."
	@echo "make clean:   Clean out paper build."
