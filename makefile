doc: doc/gh-pages/sphinx

doc/source/%.rst: %.py
	sphinx-apidoc --force --no-toc -o doc/source/ . doc

doc/gh-pages/sphinx: doc/source/*.rst doc/source/conf.py
	cd doc && make html
