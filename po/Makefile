POTFILES=$(wildcard ../lib/*.pm) $(wildcard ../lib/GUI/*.pm) ../tinyca
CATALOGS=de.mo es.mo cs.mo

all: $(CATALOGS)

.po.mo:
	msgfmt -o $@ $<
	install -m 644 $@ ../locale/`basename $@ .mo`/LC_MESSAGES/tinyca.mo

%.po: tinyca.pot
	msgmerge -vU $@ tinyca.pot

tinyca.pot: $(POTFILES)
	xgettext --add-comments \
		--keyword=_ \
		--keyword=N_ \
		--language=C \
		-o tinyca.pot \
		$(POTFILES); \

clean:
	rm -f $(CATALOGS)
	rm -f tinyca.pot

.SUFFIXES: .po .pot .mo
