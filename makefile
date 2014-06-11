SHELL := /bin/bash

virtual_env: requirements.txt
	virtualenv virtual_env
	source virtual_env/bin/activate && pip install -r requirements.txt

doc: doc/gh-pages doc/gh-pages/sphinx

doc/gh-pages: configure_doc_autogen.sh
	./configure_doc_autogen.sh

doc/source/%.rst: %.py
	source virtual_env/bin/activate && sphinx-apidoc --force --no-toc -o doc/source/ . doc

doc/gh-pages/sphinx: virtual_env doc/source/*.rst doc/source/conf.py
	source virtual_env/bin/activate && cd doc && make html # && make coverage # (Sphinx's coverage builder doesn't seem to actually do anything...)
