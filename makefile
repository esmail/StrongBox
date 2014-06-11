doc: doc/gh-pages doc/gh-pages/sphinx

doc/gh-pages: configure_doc_autogen.sh
	./configure_doc_autogen.sh

doc/source/%.rst: %.py
	sphinx-apidoc --force --no-toc -o doc/source/ . doc

doc/gh-pages/sphinx: doc/source/*.rst doc/source/conf.py
	cd doc && make html # && make coverage # (Sphinx's coverage builder doesn't seem to actually do anything...)
